# Runtime Containment

Runtime containment is the defense-in-depth layer that prevents the
agent from escaping its sandbox and gaining unauthorized access to
the host system or network.

## Defense Layers

Ovara uses four independent containment layers. Compromise of one
layer does not grant access past the others.

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                      │
│  ┌───────────────────────────────────────────────────┐  │
│  │              AppArmor Profile                      │  │
│  │  Capability restrictions, file access control,     │  │
│  │  network restrictions, deny ptrace/dbus/mount      │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Seccomp Filter                        │  │
│  │  Whitelist of ~130 syscalls, blocks mount, ptrace, │  │
│  │  kexec, bpf, module loading                       │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │              eBPF Interceptor                      │  │
│  │  Runtime syscall monitoring, policy enforcement,   │  │
│  │  audit trail via ring buffer                       │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  ┌───────────────────────────────────────────────────┐  │
│  │              Firecracker MicroVM                    │  │
│  │  Hardware isolation via KVM, read-only rootfs,     │  │
│  │  resource limits, network isolation                │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## AppArmor

**File:** `security/apparmor/ovara-gateway`

The AppArmor profile enforces mandatory access control on the
gateway binary:

- **Capabilities:** Only `net_bind_service` is granted (for binding
  to ports < 1024)
- **Deny rules:** Explicit denial of `sys_admin`, `sys_rawio`,
  `sys_ptrace`, `sys_module`, `sys_boot`, `mount`, `kexec`,
  `bpf`, `module loading`
- **File access:** Read-only access to `/etc`, `/usr`; read-write
  only to `var/data` and `var/log`
- **Network:** Only outbound to configured control plane

## Seccomp

**File:** `security/sandbox/seccomp-profile.json`

The Seccomp profile is a syscall allowlist:

- **Allowed:** ~130 syscalls for normal operation (read, write,
  open, close, mmap, etc.)
- **Blocked:** `mount`, `ptrace`, `kexec_load`, `bpf`, `module_*`,
  `init_module`, `delete_module`, `reboot`, `setns`
- **Default action:** `SCMP_ACT_KILL_PROCESS` for unknown syscalls

## eBPF Interceptor

**File:** `security/ebpf/ovara_interceptor.c`

The eBPF interceptor provides runtime syscall monitoring:

- **Attach points:** `sys_enter` and `sys_exit` for all syscalls
- **BPF maps:** ring buffer for events, hash map for policy state
- **Policy enforcement:** Can drop or modify syscalls based on
  policy
- **Audit trail:** All events logged to ring buffer for offline
  analysis

## Firecracker MicroVM

**File:** `security/sandbox/firecracker.yaml`

The Firecracker configuration provides hardware-isolated execution:

- **KVM-backed:** Hardware virtualization via KVM
- **Read-only rootfs:** Filesystem is mounted read-only
- **Resource limits:** CPU, memory, and disk quotas enforced
- **Network isolation:** Optional network namespace isolation

## Attack Patterns Mitigated

### 1. Privilege Escalation via Mount

An attacker attempts to mount a new filesystem to gain access.

**Defense:** AppArmor denies `mount`, Seccomp blocks the `mount`
syscall. Even if both are bypassed, the Firecracker microVM does
not allow mount.

### 2. Kernel Module Loading

An attacker attempts to load a malicious kernel module.

**Defense:** AppArmor denies `sys_module`, Seccomp blocks
`init_module` and `finit_module`. Requires root + CAP_SYS_MODULE.

### 3. Ptrace-Based Process Injection

An attacker attempts to ptrace the gateway or another process.

**Defense:** AppArmor denies `sys_ptrace`, Seccomp blocks the
`ptrace` syscall.

### 4. Filesystem Escape

An attacker attempts to access files outside the agent's allowed
scope.

**Defense:** AppArmor restricts file access. The eBPF interceptor
can detect and block unauthorized file access.

### 5. Network Egress to Internal Services

An attacker attempts to reach internal services that are not the
control plane.

**Defense:** AppArmor restricts network access. Network policies
can be enforced at the network namespace level (Firecracker).

### 6. Side-Channel Attacks

An attacker attempts Spectre/Meltdown-style side-channel attacks.

**Defense:** Firecracker provides hardware isolation that mitigates
many side channels. Full mitigation is out of scope for V1.

## Validation

Each layer is validated before deployment:

```bash
# AppArmor
sudo apparmor_parser -Q security/apparmor/ovara-gateway

# Seccomp
python3 -c "import json; json.load(open('security/sandbox/seccomp-profile.json'))"

# eBPF (requires kernel headers)
cd security/ebpf && make

# Firecracker
# Requires KVM-enabled host
firecracker --validate security/sandbox/firecracker.yaml
```

The Makefile has a `security-check` target that runs these
validations:

```bash
make security-check
```

## Testing in CI

The security profiles are validated in CI:

- AppArmor profile is parsed (syntax check)
- Seccomp profile is valid JSON
- eBPF source compiles
- Firecracker YAML is valid

Full runtime testing of the profiles requires a Linux host with
KVM and AppArmor support. This is recommended before production
deployment but not part of standard CI.

## Limitations

- **AppArmor is Linux-only.** macOS and Windows deployments do
  not have AppArmor. On macOS, sandbox-exec provides similar
  functionality. On Windows, AppContainer can be used.
- **eBPF requires kernel 4.18+.** Older kernels do not support
  the BPF features used.
- **Firecracker requires KVM.** Virtualized or cloud environments
  must have nested virtualization enabled.
- **No defense against kernel-level vulnerabilities.** A kernel
  bug could potentially bypass all four layers.

## Related Documents

- [Attack Vectors](attack_vectors.md)
- [Recursive Execution Threats](recursive_execution_threats.md)
- [Trust Boundaries](trust_boundaries.md)
