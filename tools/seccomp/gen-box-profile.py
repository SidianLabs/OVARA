#!/usr/bin/env python3
"""Derive the tier 2 box's seccomp profile from Docker's default.

Docker's default profile (github.com/moby/profiles, seccomp/default.json)
lets socket() open some thirty address families, several with a history of
kernel bugs (TIPC, RDS, CAN, Bluetooth, XDP, KCM, Phonet, ...). An agent in
an ovara box needs four: AF_UNIX, AF_INET and AF_INET6 (its traffic and the
relay to the proxy), and AF_NETLINK with protocol NETLINK_ROUTE (listing
interfaces). And process_vm_writev is removed: it writes another process's
memory, the move that could swap a program's arguments after the command
gate has read them (the gate itself needs only ptrace). Everything else in
Docker's profile is kept as it is.

  python3 tools/seccomp/gen-box-profile.py default.json > proxy/cmd/ovara/box-seccomp.json
"""
import json
import sys

AF_UNIX, AF_INET, AF_INET6, AF_NETLINK = 1, 2, 10, 16
NETLINK_ROUTE = 0

src = json.load(open(sys.argv[1]))
rules = [r for r in src["syscalls"] if "socket" not in r["names"]]
for r in rules:
    r["names"] = [n for n in r["names"] if n != "process_vm_writev"]
rules = [r for r in rules if r["names"]]
# a rule naming socket together with other syscalls would lose them: refuse
for r in src["syscalls"]:
    if "socket" in r["names"] and r["names"] != ["socket"]:
        sys.exit("unexpected: socket shares a rule with %s" % r["names"])

def allow(*args):
    return {"names": ["socket"], "action": "SCMP_ACT_ALLOW",
            "args": [{"index": i, "value": v, "op": "SCMP_CMP_EQ"} for i, v in args]}

rules += [
    allow((0, AF_UNIX)),
    allow((0, AF_INET)),
    allow((0, AF_INET6)),
    allow((0, AF_NETLINK), (2, NETLINK_ROUTE)),
]
src["syscalls"] = rules
json.dump(src, sys.stdout, indent=1, sort_keys=False)
sys.stdout.write("\n")
