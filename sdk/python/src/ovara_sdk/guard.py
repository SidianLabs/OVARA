"""A tool guard for agent frameworks.

Every in-process tool call (a function the model asked for: send an email,
delete a file, run a query) is decided by the Ovara gateway before it runs,
held for a person when policy says so, and reported afterwards, so the
decision and what happened share one record. The guard holds the AGENT
credential only: it can ask and report, never approve.

    guard = ToolGuard("http://127.0.0.1:8080", api_key=token, agent="support-bot")

    @guard.tool("send_email")
    def send_email(to: str, subject: str, body: str) -> str: ...

    tool = StructuredTool.from_function(guard.wrap(delete_file, "delete_file"))

A call the policy denies raises ``ToolDenied`` and the function never runs.
A call the policy holds opens an approval (what a person sees is the tool,
the size and hash of its arguments and a preview with secret-looking
values masked) and waits ``wait_seconds`` for the answer; past that it
raises ``ToolHeld`` with the approval id, and the identical call made again
gets the approval back once it is answered. An approved call is claimed
(single use) before it runs. The guard fails closed: when the gateway
cannot be reached, the tool does not run.
"""
from __future__ import annotations

import asyncio
import datetime
import functools
import hashlib
import inspect
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

ACTION_TYPE = "tool.call"
PREVIEW_LIMIT = 2048
MASK = "***"

_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
_SECRET_KEY = re.compile(
    r"(pass(word|wd|phrase)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|cookie|session)",
    re.IGNORECASE,
)
_log = logging.getLogger("ovara_sdk.guard")


def tool_resource(name: str) -> str:
    """The policy resource for a tool: ``tool:<name>`` with the MCP gate's
    escaping (letters, digits, ``_``, ``-`` and ``.`` kept, every other byte
    ``%XX``), so a name cannot carry a wildcard, a separator or white space."""
    out = []
    for b in name.encode("utf-8"):
        c = chr(b)
        out.append(c if c in _SAFE else "%%%02X" % b)
    return "tool:" + "".join(out)


def canonical_arguments(arguments: Any) -> bytes:
    """One byte string for one set of arguments: sorted keys, no spaces."""
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False).encode("utf-8")


def mask_secrets(value: Any) -> Any:
    """A copy with the values of secret-looking keys replaced, at any depth."""
    if isinstance(value, dict):
        return {k: (MASK if isinstance(k, str) and _SECRET_KEY.search(k) else mask_secrets(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_secrets(v) for v in value]
    return value


class GuardError(Exception):
    """The guard could not get an answer: the tool did not run."""


class ToolDenied(GuardError):
    """The gateway, the policy or a person said no: the tool did not run."""

    def __init__(self, call: "GuardedCall", reason: str) -> None:
        self.call = call
        self.reason = reason
        super().__init__(f"tool {call.tool!r} not run: {reason}")


class ToolHeld(GuardError):
    """The call waits on a person. ``approval_id`` names the approval; the
    identical call made again after the answer runs (or is refused)."""

    def __init__(self, call: "GuardedCall", retry_after: float) -> None:
        self.call = call
        self.approval_id = call.approval_id
        self.retry_after = retry_after
        super().__init__(
            f"tool {call.tool!r} is held for approval {call.approval_id}: ask again after {retry_after:g}s"
        )


@dataclass
class GuardedCall:
    """The record of one call through the guard."""

    tool: str
    resource: str
    arguments_sha256: str
    arguments_bytes: int
    decision_id: str = ""
    decision: str = ""
    rule: str = ""
    reasons: list[str] = field(default_factory=list)
    approval_id: str = ""
    approval_status: str = ""
    resolved_by: str = ""
    claimed: bool = False
    outcome_status: str = ""
    outcome_recorded: Optional[bool] = None
    duration_ms: int = 0


class ToolGuard:
    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        environment: str = "local",
        agent: Optional[str] = None,
        framework: Optional[str] = None,
        wait_seconds: float = 60.0,
        poll_seconds: float = 1.0,
        timeout_seconds: float = 10.0,
        on_hold: Optional[Callable[["GuardedCall"], None]] = None,
        transport: Any = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.environment = environment
        self.agent = agent
        self.framework = framework
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds
        self._timeout = timeout_seconds
        self.on_hold = on_hold
        self._transport = transport
        self._sync: Optional[httpx.Client] = None
        self._async: Optional[httpx.AsyncClient] = None
        self.last: Optional[GuardedCall] = None

    # --- wrapping ---------------------------------------------------------

    def tool(self, name: Any = None) -> Callable:
        """``@guard.tool`` or ``@guard.tool("name")``."""
        if callable(name):
            return self.wrap(name)
        return lambda fn: self.wrap(fn, name)

    def wrap(self, fn: Callable, name: Optional[str] = None) -> Callable:
        """The same callable (sync or async), decided before it runs and
        reported after. The tool's name is ``name`` or the function's."""
        tool = name or getattr(fn, "__name__", None) or "tool"
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                call = await self.acheck(tool, _arguments_of(fn, args, kwargs))
                started = time.monotonic()
                try:
                    result = await fn(*args, **kwargs)
                except Exception as exc:
                    await self._areport(call, started, exc)
                    raise
                await self._areport(call, started, None)
                return result

            return guarded_async

        @functools.wraps(fn)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            call = self.check(tool, _arguments_of(fn, args, kwargs))
            started = time.monotonic()
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                self._report(call, started, exc)
                raise
            self._report(call, started, None)
            return result

        return guarded

    def langchain(self, tool: Any, name: Optional[str] = None) -> Any:
        """Guard a LangChain tool object in place: its ``func`` and
        ``coroutine`` are wrapped under the tool's name. Returns the tool."""
        tool_name = name or getattr(tool, "name", None) or type(tool).__name__
        wrapped = 0
        for attr in ("func", "coroutine"):
            fn = getattr(tool, attr, None)
            if callable(fn):
                setattr(tool, attr, self.wrap(fn, tool_name))
                wrapped += 1
        if not wrapped:
            raise TypeError("not a LangChain tool with a func or coroutine: wrap the function with guard.wrap before building the tool")
        return tool

    # --- deciding ---------------------------------------------------------

    def check(self, tool: str, arguments: Any = None) -> GuardedCall:
        """Have one call decided. Returns when it may run; raises
        ``ToolDenied`` or ``ToolHeld`` when it may not."""
        call = self._new_call(tool, arguments)
        steps = self._protocol(call)
        try:
            step = next(steps)
            while True:
                if step[0] == "sleep":
                    time.sleep(step[1])
                    step = steps.send(None)
                    continue
                step = steps.send(self._request(self._sync_client(), *step))
        except StopIteration:
            return call

    async def acheck(self, tool: str, arguments: Any = None) -> GuardedCall:
        """``check`` for an async framework."""
        call = self._new_call(tool, arguments)
        steps = self._protocol(call)
        try:
            step = next(steps)
            while True:
                if step[0] == "sleep":
                    await asyncio.sleep(step[1])
                    step = steps.send(None)
                    continue
                step = steps.send(await self._arequest(self._async_client(), *step))
        except StopIteration:
            return call

    def _protocol(self, call: GuardedCall):
        """The decision sequence, independent of how requests are made:
        check, then for an escalation create, poll, claim."""
        status, d = yield ("POST", "/v1/runtime/check", self._check_body(call))
        if status != 200:
            raise GuardError(f"tool {call.tool!r} not run: the gateway answered HTTP {status} to the check")
        call.decision_id = str(d.get("decision_id") or "")
        call.decision = str(d.get("decision") or "")
        call.rule = str(d.get("matched_rule") or "")
        call.reasons = [str(r) for r in (d.get("reason_codes") or [])]
        if call.decision == "allow":
            return
        if call.decision != "escalate":
            raise ToolDenied(call, _why(call, "denied by policy"))
        status, a = yield ("POST", "/v1/approval/create", {"decision_id": call.decision_id})
        if status not in (200, 201):
            raise ToolDenied(call, f"held for a person, but no approval could be opened (HTTP {status})")
        call.approval_id = str(a.get("approval_id") or "")
        call.approval_status = str(a.get("status") or "pending")
        call.resolved_by = str(a.get("resolved_by") or "")
        if call.approval_status == "pending" and self.on_hold is not None:
            self.on_hold(call)
        deadline = time.monotonic() + max(self.wait_seconds, 0.0)
        while call.approval_status == "pending":
            if time.monotonic() >= deadline:
                raise ToolHeld(call, max(self.poll_seconds, 1.0))
            yield ("sleep", min(self.poll_seconds, max(deadline - time.monotonic(), 0.0)), None)
            status, a = yield ("GET", f"/v1/approval/{call.approval_id}", None)
            if status == 200:
                call.approval_status = str(a.get("status") or "pending")
                call.resolved_by = str(a.get("resolved_by") or "")
            elif status == 404:
                raise ToolDenied(call, "the approval is gone")
        if call.approval_status != "approved":
            who = f" by {call.resolved_by}" if call.resolved_by else ""
            raise ToolDenied(call, f"{call.approval_status}{who}")
        status, c = yield ("POST", f"/v1/approval/{call.approval_id}/claim", None)
        if status == 200 and c.get("claimed") is True:
            call.claimed = True
            return
        if status == 409:
            raise ToolDenied(call, "the approval was already used: ask again")
        raise ToolDenied(call, f"the approval could not be claimed (status {c.get('status') or status})")

    # --- reporting --------------------------------------------------------

    def _outcome_body(self, call: GuardedCall, started: float, exc: Optional[BaseException]) -> dict:
        call.duration_ms = int((time.monotonic() - started) * 1000)
        call.outcome_status = "error" if exc is not None else "ok"
        body: dict = {"decision_id": call.decision_id, "status": call.outcome_status, "duration_ms": call.duration_ms}
        if exc is not None:
            body["error"] = f"{type(exc).__name__}: {exc}"[:600]
        return body

    def _report(self, call: GuardedCall, started: float, exc: Optional[BaseException]) -> None:
        body = self._outcome_body(call, started, exc)
        try:
            status, _ = self._request(self._sync_client(), "POST", "/v1/runtime/outcome", body)
            call.outcome_recorded = status == 200
        except GuardError:
            call.outcome_recorded = False
        if not call.outcome_recorded:
            _log.warning("ovara: outcome of tool %r (decision %s) was not recorded", call.tool, call.decision_id)

    async def _areport(self, call: GuardedCall, started: float, exc: Optional[BaseException]) -> None:
        body = self._outcome_body(call, started, exc)
        try:
            status, _ = await self._arequest(self._async_client(), "POST", "/v1/runtime/outcome", body)
            call.outcome_recorded = status == 200
        except GuardError:
            call.outcome_recorded = False
        if not call.outcome_recorded:
            _log.warning("ovara: outcome of tool %r (decision %s) was not recorded", call.tool, call.decision_id)

    # --- plumbing ---------------------------------------------------------

    def _new_call(self, tool: str, arguments: Any) -> GuardedCall:
        canon = canonical_arguments(arguments if arguments is not None else {})
        call = GuardedCall(
            tool=tool,
            resource=tool_resource(tool),
            arguments_sha256=hashlib.sha256(canon).hexdigest(),
            arguments_bytes=len(canon),
        )
        call._preview = _preview(arguments)  # type: ignore[attr-defined]
        self.last = call
        return call

    def _check_body(self, call: GuardedCall) -> dict:
        context = {
            "tool": call.tool,
            "arguments": getattr(call, "_preview", ""),
            "arguments_bytes": str(call.arguments_bytes),
            "arguments_sha256": call.arguments_sha256,
        }
        if self.framework:
            context["framework"] = self.framework
        if self.agent:
            context["agent"] = self.agent
        return {
            "action_type": ACTION_TYPE,
            "resource": call.resource,
            "environment": self.environment,
            "metadata": {"proxy_context": context},
            "nonce": uuid.uuid4().hex,
            "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _sync_client(self) -> httpx.Client:
        if self._sync is None:
            self._sync = httpx.Client(timeout=self._timeout, transport=self._transport)
        return self._sync

    def _async_client(self) -> httpx.AsyncClient:
        if self._async is None:
            self._async = httpx.AsyncClient(timeout=self._timeout, transport=self._transport)
        return self._async

    def _request(self, client: httpx.Client, method: str, path: str, body: Any) -> tuple[int, dict]:
        try:
            resp = client.request(method, self._base_url + path, headers=self._headers(), json=body)
        except httpx.HTTPError as exc:
            raise GuardError(f"the gateway could not be reached ({exc.__class__.__name__}): the tool did not run") from exc
        return resp.status_code, _json_of(resp)

    async def _arequest(self, client: httpx.AsyncClient, method: str, path: str, body: Any) -> tuple[int, dict]:
        try:
            resp = await client.request(method, self._base_url + path, headers=self._headers(), json=body)
        except httpx.HTTPError as exc:
            raise GuardError(f"the gateway could not be reached ({exc.__class__.__name__}): the tool did not run") from exc
        return resp.status_code, _json_of(resp)

    def close(self) -> None:
        if self._sync is not None:
            self._sync.close()
            self._sync = None

    async def aclose(self) -> None:
        if self._async is not None:
            await self._async.aclose()
            self._async = None
        self.close()


def _json_of(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _why(call: GuardedCall, default: str) -> str:
    parts = []
    if call.rule:
        parts.append(f"rule {call.rule!r}")
    if call.reasons:
        parts.append(", ".join(call.reasons))
    return (default + " (" + "; ".join(parts) + ")") if parts else default


def _preview(arguments: Any) -> str:
    if arguments is None:
        return ""
    text = json.dumps(mask_secrets(arguments), sort_keys=True, default=str, ensure_ascii=False)
    if len(text) > PREVIEW_LIMIT:
        text = text[:PREVIEW_LIMIT] + "…"
    return text


def _arguments_of(fn: Callable, args: tuple, kwargs: dict) -> Any:
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
    except (TypeError, ValueError):
        return {"args": list(args), "kwargs": dict(kwargs)}
    return dict(bound.arguments)
