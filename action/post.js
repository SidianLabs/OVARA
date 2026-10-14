// Ovara GitHub Action, post step: stop the Ovara the main step started and
// write what the job did to the job summary: the receipts, verified, and
// under the observe profile the rules a strict policy would have needed.
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

function state(n) { return process.env["STATE_" + n] || ""; }
function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function alive(pid) { try { process.kill(pid, 0); return true; } catch (e) { return false; } }
function out(bin, args) { return spawnSync(bin, args, { encoding: "utf8" }); }

function main() {
  const pid = Number(state("pid")), dir = state("dir"), bin = state("bin"), profile = state("profile");
  if (!dir || !bin) { console.log("nothing to stop: the main step did not start Ovara"); return; }
  if (pid && alive(pid)) {
    try { process.kill(pid, "SIGTERM"); } catch (e) { /* already gone */ }
    for (let i = 0; i < 60 && alive(pid); i++) sleep(250);
    if (alive(pid)) { try { process.kill(pid, "SIGKILL"); } catch (e) { /* gone */ } }
  }
  const log = out(bin, ["log", "-dir", dir, "-n", "0"]);
  let summary = "## Ovara\n\n```\n" + ((log.stdout || "") + (log.stderr || "")).trim() + "\n```\n";
  if (log.status !== 0) {
    summary += "\n**The receipt chain did not verify.** Treat the record as suspect.\n";
    console.log("::warning::the receipt chain did not verify");
  }
  if (profile === "observe") {
    const s = out(bin, ["policy", "suggest", "-dir", dir]);
    summary += "\nThe rules a strict policy would have needed for this run (`ovara policy suggest`):\n\n```json\n" + (s.stdout || "").trim() + "\n```\n" + (s.stderr || "").trim() + "\n";
  }
  summary += "\nEvidence: `" + path.join(dir, "var", "receipts.jsonl") + "` with `var/receipt_pubkey.hex` (upload them as an artifact to keep them; `ovara log -receipts ... -pubkey ...` verifies them anywhere).\n";
  try {
    const adir = path.join(dir, "var", "attestations");
    const files = fs.readdirSync(adir).filter((n) => n.endsWith(".intoto.json")).sort();
    if (files.length) {
      const v = out(bin, ["attest", "verify", "-dir", dir]);
      summary += "\nAttestation: `" + path.join(adir, files[files.length - 1]) + "`, an in-toto statement signed with the receipt key (`ovara attest verify FILE -receipts ... -pubkey ...` checks it anywhere):\n\n```\n" + ((v.stdout || "") + (v.stderr || "")).trim() + "\n```\n";
      if (v.status !== 0) console.log("::warning::the run's attestation did not verify");
    }
  } catch (e) { /* no attestation was written */ }
  const f = process.env.GITHUB_STEP_SUMMARY;
  if (f) fs.appendFileSync(f, summary); else console.log(summary);
}

main();
