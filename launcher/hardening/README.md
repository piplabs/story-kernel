# hardening/

OS hardening policies baked into the image. The goal: even if an
operator has full root access inside the running TD, they cannot
extract sealed material or inject code into running story-kernel
processes.

## Contents

| File | Purpose |
|---|---|
| `sysctl.conf` | Runtime kernel tightening (ptrace_scope=3, kexec disabled, BPF off, no coredumps, network hardening, …) |
| `modprobe-blacklist.conf` | Blocks dangerous/legacy modules (kprobes, /dev/mem, rare fs/net, USB storage) via `install … /bin/false` |
| `users.conf` | Reproducible system users — the `story-kernel` runtime user (nologin, no writable home) |
| `install.sh` | Applies the tree to a rootfs (invoked by `mkosi.postinst`): installs sysctl/modprobe policy, creates users deterministically |
| `README.md` | This file |

## Controls applied

- No SSH daemon; no shell after boot handoff
- `kernel.yama.ptrace_scope = 3` (no ptrace at all)
- `kernel.kexec_load_disabled = 1`
- `kernel.dmesg_restrict = 1`, `kernel.kptr_restrict = 2`
- Unprivileged BPF + JIT disabled; user namespaces disabled; SysRq off
- `/dev/mem`, `/dev/kmem`, `/dev/port` blocked (sysctl + modprobe + udev)
- No setuid binaries shipped; core dumps disabled everywhere (sealed memory never hits disk)
- Read-only `/etc`, `/usr` enforced by dm-verity
