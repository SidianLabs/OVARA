#!/usr/bin/env python3
"""A second, independent implementation of the Ovara C1/C2 contracts.

This is deliberately a *different* implementation from the Go reference: it
exists to prove the contracts in spec/ are precise enough to build from, and
to catch anything that only works because of the reference's internals
(sandbox-standard.md §9.4). It depends only on the Python standard library.

Run it against the committed vectors:

    python3 -I conformance/impl-python/conformance_check.py

It reads ../vectors/*.json, recomputes each result with the functions below,
and exits non-zero on any disagreement with the reference. C4 (receipts) is
already covered by the Python SDK verifier (sdk/python); C3/C5 need a live
deployment (see conformance/README.md).
"""

import ipaddress
import json
import os
import posixpath
import sys
import urllib.parse


# --- C1: the resource model -------------------------------------------------

def is_method_token(s: str) -> bool:
    """An HTTP-method-shaped token: non-empty, ASCII letters only."""
    return len(s) > 0 and all(("A" <= c <= "Z") or ("a" <= c <= "z") for c in s)


def is_ref_list(s: str) -> bool:
    """The git-ref suffix the proxy may append after a URL resource."""
    if s in ("git-receive-pack", "git-receive-pack(truncated)"):
        return True
    for ref in s.split(","):
        if ref.endswith("(delete)"):
            ref = ref[: -len("(delete)")]
        if not ref.startswith("refs/"):
            return False
        for c in ref[5:]:
            ok = (
                ("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9")
                or c in "/._-~"
            )
            if not ok:
                return False
    return True


def is_url_resource(resource: str) -> bool:
    """True for "scheme://..." or "METHOD scheme://..."; a shell line that
    merely contains "://" is not one."""
    rest = resource
    i = resource.find(" ")
    if i > 0 and is_method_token(resource[:i]):
        rest = resource[i + 1:]
    j = rest.find("://")
    if j <= 0:
        return False
    for k, c in enumerate(rest[:j]):
        if not (("a" <= c <= "z") or ("A" <= c <= "Z")
                or (k > 0 and (("0" <= c <= "9") or c in "+-."))):
            return False
    return True


def canonical_resource(resource: str):
    """C1 §2: normalise "METHOD scheme://authority/path[?query][ refs]".
    Returns the canonical string, or None when the input is not canonical."""
    method, rest = resource, ""
    i = resource.find(" ")
    if i > 0:
        if not is_method_token(resource[:i]):
            return None
        method, rest = resource[:i].upper(), resource[i + 1:].strip()

    suffix = ""
    j = rest.find(" ")
    if j > 0:
        tail = rest[j + 1:].strip()
        if not is_ref_list(tail):
            return None
        suffix, rest = " " + tail, rest[:j]

    sr = urllib.parse.urlsplit(rest)
    scheme = sr.scheme.lower()
    if scheme == "" or sr.netloc == "":
        return None
    if "@" in sr.netloc:  # userinfo never participates in authorization
        return None

    # authority -> host, port (IPv6 in brackets)
    auth = sr.netloc
    if auth.startswith("["):
        k = auth.find("]")
        if k < 0:
            return None
        host, after = auth[1:k], auth[k + 1:]
        port = after[1:] if after.startswith(":") else ""
    elif ":" in auth:
        host, port = auth.rsplit(":", 1)
    else:
        host, port = auth, ""

    host = host.lower().rstrip(".")
    if host == "" or "%" in host:
        return None
    if ":" in host:  # a colon means an IPv6 literal, and it must be one
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None

    # Reject dot segments in the DECODED path (raw or percent-encoded).
    for seg in urllib.parse.unquote(sr.path).split("/"):
        if seg in (".", ".."):
            return None

    if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
        port = ""

    esc = sr.path
    clean = posixpath.normpath("/" + esc.lstrip("/"))
    if esc.endswith("/") and clean != "/":
        clean += "/"

    out = (method + " ") if method else ""
    out += scheme + "://"
    out += ("[" + host + "]") if ":" in host else host
    if port:
        out += ":" + port
    out += clean
    if sr.query:
        out += "?" + sr.query
    out += suffix
    return out


# --- C2: policy matching and precedence -------------------------------------

def specificity(pattern: str) -> int:
    return len(pattern) - pattern.count("*")


def glob_match(pattern: str, s: str) -> bool:
    parts = pattern.split("*")
    pos = 0
    for i, p in enumerate(parts):
        if p == "":
            continue
        idx = s.find(p, pos)
        if idx < 0:
            return False
        if i == 0 and idx != 0:
            return False
        pos = idx + len(p)
    last = parts[-1]
    if last != "" and not s.endswith(last):
        return False
    return True


def authority_segment(url_glob: str) -> str:
    i = url_glob.find("://")
    if i < 0:
        return ""
    rest = url_glob[i + 3:]
    j = rest.find("/")
    return rest[:j] if j >= 0 else rest


def canon_host(canon_url: str) -> str:
    i = canon_url.find("://")
    if i < 0:
        return ""
    rest = canon_url[i + 3:]
    j = rest.find("/")
    if j >= 0:
        rest = rest[:j]
    if rest.startswith("["):
        k = rest.find("]")
        if k >= 0:
            return rest[1:k]
    k = rest.rfind(":")
    if k >= 0:
        return rest[:k]
    return rest


def longest_literal(s: str) -> str:
    best, cur = "", ""
    for r in s:
        if r == "*":
            if len(cur) > len(best):
                best = cur
            cur = ""
        else:
            cur += r
    if len(cur) > len(best):
        best = cur
    return best


def host_literal_matches(pattern: str, canon_url: str) -> bool:
    p_auth = authority_segment(pattern)
    if p_auth == "":
        return True
    host = canon_host(canon_url)
    if host == "":
        return True
    lit = longest_literal(p_auth).lower().rstrip(".")
    k = lit.rfind(":")
    if k > 0 and "]" not in lit[k + 1:]:
        lit = lit[:k]
    lit = lit.removesuffix("]").removeprefix("[")
    if lit == "":
        return True
    if not p_auth.startswith("*"):
        return host == lit
    if lit.startswith("."):
        return host.endswith(lit)
    return host == lit or host.endswith("." + lit)


def match_canonical(pattern: str, canon: str) -> bool:
    if pattern == "":
        return True
    canon_url = canon
    i = canon.find(" ")
    if i > 0:
        canon_url = canon[i + 1:]
        j = pattern.find(" ")
        if j > 0 and "*" not in pattern[:j]:
            if pattern[:j].lower() != canon[:i].lower():
                return False
            pattern = pattern[j + 1:].strip()
    if "://" in pattern and not host_literal_matches(pattern, canon_url):
        return False
    return glob_match(pattern, canon_url)


def match_resource(pattern: str, resource: str) -> bool:
    if pattern == "":
        return True
    if not is_url_resource(resource):
        return glob_match(pattern, resource)
    canon = canonical_resource(resource)
    if canon is None:
        return False
    return match_canonical(pattern, canon)


# --- the runner -------------------------------------------------------------

def load(name):
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "vectors", name), encoding="utf-8") as f:
        return json.load(f)["vectors"]


def main() -> int:
    fails = 0
    checked = 0

    for v in load("canonical.json"):
        got = canonical_resource(v["input"])
        checked += 1
        if got != v["canonical"]:
            fails += 1
            print(f"C1 canonical({v['input']!r}) = {got!r}, want {v['canonical']!r}")

    for v in load("match.json"):
        got = match_resource(v["pattern"], v["resource"])
        checked += 1
        if got != v["match"]:
            fails += 1
            print(f"C1/C2 match({v['pattern']!r}, {v['resource']!r}) = {got}, want {v['match']}")

    for v in load("specificity.json"):
        got = specificity(v["pattern"])
        checked += 1
        if got != v["specificity"]:
            fails += 1
            print(f"C2 specificity({v['pattern']!r}) = {got}, want {v['specificity']}")

    print(f"\n{checked} vectors checked, {fails} mismatch(es)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
