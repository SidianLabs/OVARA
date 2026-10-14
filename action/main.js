// Ovara GitHub Action, main step: build Ovara from this checkout, start it
// for the job, and hand every later step the environment that routes it
// through Ovara (keys stay with Ovara; the steps see placeholders). The post
// step (post.js) stops it and writes the receipts summary.
"use strict";
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");

function input(name, def) {
  const v = process.env["INPUT_" + name.replace(/ /g, "_").toUpperCase()];
  return v === undefined || v === "" ? def : v;
}
function appendTo(fileEnv, text) {
  const f = process.env[fileEnv];
  if (!f) throw new Error(fileEnv + " is not set: this runs as a GitHub Actions step");
  fs.appendFileSync(f, text.endsWith("\n") ? text : text + "\n");
}
function run(cmd, args, opts) {
  const r = spawnSync(cmd, args, Object.assign({ stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" }, opts || {}));
  if (r.error) throw r.error;
  return r;
}
function must(r, what) {
  if (r.status !== 0) throw new Error(what + " failed (exit " + r.status + ")\n" + (r.stdout || "") + (r.stderr || ""));
  return r;
}
function tail(file, n) {
  try { return fs.readFileSync(file, "utf8").split("\n").slice(-n).join("\n"); } catch (e) { return ""; }
}
function waitPort(hostPort, ms) {
  const i = hostPort.lastIndexOf(":");
  const host = hostPort.slice(0, i) || "127.0.0.1", port = Number(hostPort.slice(i + 1));
  const deadline = Date.now() + ms;
  return new Promise((resolve, reject) => {
    (function attempt() {
      const s = net.connect({ host: host, port: port });
      s.once("connect", () => { s.destroy(); resolve(); });
      s.once("error", () => { s.destroy(); if (Date.now() > deadline) reject(new Error("timeout")); else setTimeout(attempt, 250); });
    })();
  });
}

async function main() {
  if (os.platform() === "win32") throw new Error("the Ovara action runs on Linux and macOS runners today");
  const root = path.resolve(__dirname, "..");
  const tmp = process.env.RUNNER_TEMP || os.tmpdir();
  const dir = path.join(tmp, "ovara");
  let bin = input("binary", "");
  if (!bin) {
    bin = path.join(tmp, "ovara-bin", "ovara");
    console.log("::group::building ovara from " + root);
    fs.mkdirSync(path.dirname(bin), { recursive: true });
    must(run("go", ["build", "-trimpath", "-o", bin, "./cmd/ovara"], {
      cwd: path.join(root, "proxy"), stdio: "inherit", env: Object.assign({}, process.env, { CGO_ENABLED: "0" }),
    }), "go build");
    console.log("::endgroup::");
  }
  const profile = input("profile", "strict");
  fs.rmSync(dir, { recursive: true, force: true });
  must(run(bin, ["init", dir, "-profile", profile]), "ovara init");

  // the job's own policy, or extra rules in front of the default ones
  const policyPath = path.join(dir, "policy.json");
  const policyIn = input("policy", "");
  if (policyIn) fs.copyFileSync(path.resolve(process.env.GITHUB_WORKSPACE || ".", policyIn), policyPath);
  const rulesIn = input("rules", "");
  if (rulesIn) {
    const rules = JSON.parse(rulesIn);
    if (!Array.isArray(rules)) throw new Error("rules: want a JSON array of rules");
    const doc = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    doc.rules = rules.concat(doc.rules || []);
    fs.writeFileSync(policyPath, JSON.stringify(doc, null, 2) + "\n");
  }
  // how long a request without a rule is held before the agent is told to retry
  const proxyPath = path.join(dir, "proxy.json");
  const pcfg = JSON.parse(fs.readFileSync(proxyPath, "utf8"));
  const hold = Number(input("hold-seconds", "10"));
  if (!Number.isInteger(hold) || hold < 1) throw new Error("hold-seconds: want a whole number of seconds");
  pcfg.escalate_timeout_sec = hold;
  // approvals from Slack: the token stays in this step's env, read by ovara run
  const slackChannel = input("slack-channel", "");
  if (slackChannel) {
    if (!process.env.OVARA_SLACK_TOKEN) throw new Error("slack-channel is set but OVARA_SLACK_TOKEN is not: put the bot token in this step's env, from a secret");
    const approvers = input("slack-approvers", "").split(/[\s,]+/).filter(Boolean);
    pcfg.chat = { slack: { channel: slackChannel, allowed_users: approvers, token_env: "OVARA_SLACK_TOKEN" } };
  }
  fs.writeFileSync(proxyPath, JSON.stringify(pcfg, null, 2) + "\n");

  // Ovara for the job; its log is in the deployment directory
  const logFd = fs.openSync(path.join(dir, "run.log"), "a");
  const child = spawn(bin, ["run", "-dir", dir, "-ui", "off"], { detached: true, stdio: ["ignore", logFd, logFd], env: process.env });
  child.unref();
  const listen = pcfg.listen_addr || "127.0.0.1:9443";
  try {
    await waitPort(listen, 60000);
  } catch (e) {
    throw new Error("ovara run did not come up on " + listen + "\n" + tail(path.join(dir, "run.log"), 40));
  }

  // the environment for every later step: through Ovara, with Ovara's CA,
  // keys replaced by placeholders, other secret-looking variables emptied
  const env = must(run(bin, ["env", "-dir", dir, "-shell", "github"]), "ovara env").stdout;
  const lines = env.split("\n").filter((l) => l && !l.startsWith("#"));
  for (const l of lines) {
    const m = /^HTTPS_PROXY=http:\/\/agent:([^@]+)@/.exec(l);
    if (m) console.log("::add-mask::" + m[1]);
  }
  appendTo("GITHUB_ENV", lines.join("\n") + "\nOVARA_DIR=" + dir);
  appendTo("GITHUB_STATE", "pid=" + child.pid + "\ndir=" + dir + "\nbin=" + bin + "\nprofile=" + profile);
  appendTo("GITHUB_OUTPUT", "dir=" + dir + "\nreceipts=" + path.join(dir, "var", "receipts.jsonl") + "\nbinary=" + bin);
  console.log("Ovara is up on " + listen + " (profile " + profile + "); every later step goes through it. Deployment: " + dir);
}

main().catch((e) => {
  console.log("::error::" + e.message);
  process.exit(1);
});
