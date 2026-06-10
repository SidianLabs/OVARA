# Ovara Runtime Gateway — Security Architecture

## Security Architecture Overview

Ovara applies a **defense-in-depth** strategy with four independent security layers. Each layer operates independently: compromise of one layer does not grant access past the others.

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

**Principle of least privilege**: every layer grants only the minimum access required for the gateway to function. All other actions are denied by default.

---

## AppArmor Profile

**File**: `apparmor/ovara-gateway`

The AppArmor profile enforces mandatory access control on the gateway binary.

### Capabilities
- Only `net_bind_service` is granted (bind to ports < 1024)
- `sys_admin`, `sys_rawio`, `sys_ptrace`, `sys_module`, `sys_boot` are explicitly denied
- All other capabilities are denied by the implicit capability deny rules

### File Access
| Path | Access | Purpose |
|------|--------|---------|
| `/etc/ovara/config.json` | Read-only | Gateway configuration |
| `/var/data/ovara/**` | Read-write | Transaction logs, state |
| `/var/log/ovara/**` | Read-write | Structured logs |
| `/tmp/ovara-exec/**` | Read-write+exec | Temporary execution dir |
| `/etc/ssl/certs/**` | Read-only | TLS certificates |
| `/etc/ssl/openssl.cnf` | Read-only | OpenSSL config |
| `/etc/hostname, hosts, resolv.conf` | Read-only | Networking |
| `/usr/lib/**` | Read-only | Go runtime libraries |
| `/proc/self/**` | Read-only | Process info |

### Denied Paths
| Path | Threat |
|------|--------|
| `/proc/sys/**` | Kernel parameter modification |
| `/sys/**` | Hardware/device parameter access |
| `/dev/**` | Direct device access, /dev/mem attacks |
| `/boot/**` | Kernel image tampering |
| `/sbin/**` | Privileged binary invocation |
| `/etc/shadow` | Password hash theft |
| `/root/**` | Root credential access |
| `/proc/kcore` | Kernel memory leak |
| `/etc/passwd` (write) | User account manipulation |

### Network Restrictions
- Only TCP stream sockets (IPv4/IPv6) permitted
- UDP, raw sockets, and netlink are denied
- Port filtering (8080, 9090) enforced via iptables (see comments in profile)

### Privileged Operation Denials
- **mount**: Prevents filesystem mount/umount (container escape)
- **ptrace**: Prevents process attachment (code injection, keylogging)
- **dbus**: Prevents system bus communication (privilege escalation)

### Loading and Testing
```bash
# Load the profile
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.ovara-gateway

# Enforce mode
sudo aa-enforce /usr/local/bin/ovara-gateway

# Check status
sudo aa-status

# Review denied actions
sudo aa-logprof
```

---

## eBPF Monitoring

**File**: `ebpf/ovara_interceptor.c`

The eBPF program provides runtime syscall interception for audit and policy enforcement.

### Monitored Syscalls
| Syscall | Tracepoint | Data Collected |
|---------|-----------|----------------|
| `execve` | `tracepoint/syscalls/sys_enter_execve` | Filename, PID, UID, comm |
| `openat` | `tracepoint/syscalls/sys_enter_openat` | Filename, flags, mode, PID |
| `tcp_v4_connect` | `kprobe/tcp_v4_connect` | Dest IP, dest port, source port |

### BPF Maps
| Map Name | Type | Purpose |
|----------|------|---------|
| `events` | Ring buffer | Push events to userspace |
| `execve_allow` | Hash | Per-agent execve allowlist |
| `execve_deny` | Hash | Per-agent execve denylist |
| `openat_allow` | Hash | Per-agent file open allowlist |
| `openat_deny` | Hash | Per-agent file open denylist |
| `connect_allow` | Hash | Per-agent connection allowlist |
| `connect_deny` | Hash | Per-agent connection denylist |

### Building
```bash
cd security/ebpf
make        # produces ovara_interceptor.o and ovara_interceptor.skel.h
```

### Loading and Verification
```bash
# Load the program
sudo bpftool prog load security/ebpf/ovara_interceptor.o /sys/fs/bpf/ovara_interceptor

# List loaded programs
sudo bpftool prog list

# List maps
sudo bpftool map list

# Pin for persistence
sudo bpftool prog pin id <PROG_ID> /sys/fs/bpf/ovara_interceptor
```

---

## Sandbox Isolation (Firecracker)

**File**: `sandbox/firecracker.yaml`

Each agent code execution runs inside a Firecracker microVM, providing hardware-level isolation via KVM.

### Configuration Summary
| Setting | Value | Purpose |
|---------|-------|---------|
| `vcpu_count` | 1 | Limit CPU cores |
| `mem_size_mib` | 128 | Limit memory |
| `read_only_rootfs` | true | Prevent filesystem tampering |
| `max_processes` | 20 | Limit fork bomb potential |
| `max_file_descriptors` | 64 | Limit FD exhaustion |
| `max_runtime_seconds` | 300 | Kill after 5 minutes |
| `balloon.deflate_on_oom` | true | Reclaim memory on OOM |
| `seccomp_path` | seccomp-profile.json | Syscall filtering |

### Network Isolation
- Tap device `tap-ovara-0` with deterministic MAC
- Outbound and inbound connections disabled by default
- Can be enabled per-environment via NetworkPolicy

### Snapshot/Restore
- Snapshots enabled for fast VM startup
- Stored at `/var/lib/ovara/snapshots/`
- Version >= 0.24.0 required

### Launching
```bash
firecracker --config-file security/sandbox/firecracker.yaml
```

---

## Seccomp Restrictions

**File**: `sandbox/seccomp-profile.json`

The seccomp profile restricts the syscall surface available to the guest process.

### Design
- **Default action**: `SCMP_ACT_ERRNO` (deny all)
- **Architecture**: `SCMP_ARCH_X86_64`
- **Allowed**: ~130 syscalls needed for Go binary execution
- **Blocked**: All dangerous syscalls

### Blocked Syscalls
| Syscall | Reason |
|---------|--------|
| `mount`, `umount2` | Filesystem manipulation |
| `ptrace` | Process attachment |
| `kexec_load`, `kexec_file_load` | Kernel replacement |
| `init_module`, `delete_module` | Kernel module loading |
| `keyctl`, `add_key`, `request_key` | Kernel keyring manipulation |
| `bpf` | BPF program loading |
| `perf_event_open` | Performance counter abuse |
| `personality` | Exec domain switching |
| `unshare` | Namespace escape |

### Clone Filter
The `clone` syscall is filtered to only allow thread creation (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID), preventing namespace creation.

### Enabling with Firecracker
Set `seccomp_path` in the Firecracker config:
```yaml
seccomp_path: "/etc/ovara/sandbox/seccomp-profile.json"
```

### Verifying
```bash
# Inside the microVM, check seccomp status:
grep Seccomp /proc/self/status
# Output: Seccomp:    2  (2 = SECCOMP_MODE_FILTER)
```

---

## Enabling Security Features

### 1. AppArmor
```bash
# Install AppArmor utils
sudo apt install apparmor-utils apparmor-profiles

# Copy profile
sudo cp security/apparmor/ovara-gateway /etc/apparmor.d/usr.local.bin.ovara-gateway

# Load and enforce
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.ovara-gateway
sudo aa-enforce /usr/local/bin/ovara-gateway
```

### 2. eBPF Interceptor
```bash
# Prerequisites: Linux 5.8+, clang, llvm, bpftool, libbpf-dev

# Build
cd security/ebpf && make

# Load
sudo bpftool prog load ovara_interceptor.o /sys/fs/bpf/ovara_interceptor

# Verify
sudo bpftool prog list | grep ovara
```

### 3. Firecracker Sandbox
```bash
# Prerequisites: KVM support, Firecracker installed

# Verify KVM
ls -la /dev/kvm

# Prepare rootfs and kernel (see Firecracker getting-started guide)
# Launch
firecracker --config-file security/sandbox/firecracker.yaml
```

### 4. Seccomp Profile
```bash
# Copy profile to expected location
sudo cp security/sandbox/seccomp-profile.json /etc/ovara/sandbox/seccomp-profile.json

# Verify seccomp_path in firecracker.yaml points to this file
# Launch Firecracker — seccomp is applied automatically
```

---

## Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|------------|
| **eBPF requires Linux 5.8+** | Not available on older kernels | Use AppArmor/Seccomp as fallback |
| **AppArmor not on all distros** | CentOS/RHEL default to SELinux | Maintain SELinux profile as alternative |
| **Firecracker requires KVM** | No nested virtualization in some clouds | Use container fallback mode |
| **Seccomp cannot filter by arguments reliably** | Some syscalls need allowlists | Combine with AppArmor path restrictions |
| **eBPF monitoring overhead** | ~1-3% CPU for ring buffer events | Tune buffer size, use batched reads |
| **Firecracker cold start** | ~125ms per VM | Use snapshot/restore for warm starts |
| **AppArmor cannot filter network ports natively** | Port restrictions require iptables | Deploy companion iptables rules |
| **Seccomp profiles are architecture-specific** | Separate profiles for x86_64 and arm64 | Maintain per-architecture profiles |

---

## Security Contact

Report security vulnerabilities to the Ovara security team. Do not open public GitHub issues for security reports.
