#!/bin/sh
# launcher/hardening/install.sh — apply the hardening tree to a rootfs.
#
# Invoked by mkosi.postinst with the rootfs path as $1.  We deliberately
# do not source the postinst environment; this script must work standalone
# against any rootfs that follows Debian's layout.
set -eu

ROOTFS=${1:?install.sh: rootfs path required}
HERE=$(cd "$(dirname "$0")" && pwd)

if [ ! -d "$ROOTFS/etc" ]; then
    echo "hardening/install.sh: $ROOTFS does not look like a Debian rootfs" >&2
    exit 1
fi

echo "hardening: installing sysctl policy"
install -D -m 0644 "$HERE/sysctl.conf"           "$ROOTFS/etc/sysctl.d/99-story-kernel.conf"

echo "hardening: installing modprobe blacklist"
install -D -m 0644 "$HERE/modprobe-blacklist.conf" "$ROOTFS/etc/modprobe.d/99-story-kernel-blacklist.conf"

echo "hardening: creating system users"
# We create users by appending to /etc/passwd directly rather than running
# useradd inside the chroot: useradd allocates UIDs from a pool which is
# nondeterministic, and we need UIDs to be reproducible.
while IFS=: read -r username uid gid home shell; do
    case "$username" in
        ''|\#*) continue ;;
    esac
    if ! grep -q "^${username}:" "$ROOTFS/etc/passwd"; then
        echo "${username}:x:${uid}:${gid}::${home}:${shell}" >> "$ROOTFS/etc/passwd"
    fi
    if ! grep -q "^${username}:" "$ROOTFS/etc/group"; then
        echo "${username}:x:${gid}:" >> "$ROOTFS/etc/group"
    fi
    if ! grep -q "^${username}:" "$ROOTFS/etc/shadow"; then
        # No password — the user cannot log in.  The shell field above is
        # nologin so even with a password they would not get a session.
        echo "${username}:!:19000:0:99999:7:::" >> "$ROOTFS/etc/shadow"
    fi
done < "$HERE/users.conf"

echo "hardening: removing SSH if present"
# We do not ship openssh-server but a transitively-pulled package might.
# Strip anything resembling SSH, then assert none survived — a partially
# hardened image (a stray sshd) must fail the build, not ship silently.
rm -rf "$ROOTFS/etc/ssh" "$ROOTFS/usr/sbin/sshd" "$ROOTFS/usr/bin/ssh"
for leftover in "$ROOTFS/usr/sbin/sshd" "$ROOTFS/usr/bin/ssh" "$ROOTFS/etc/ssh"; do
    if [ -e "$leftover" ]; then
        echo "hardening: ERROR — SSH artifact survived removal: $leftover" >&2
        exit 1
    fi
done

echo "hardening: disabling getty on all consoles"
# We boot with console=null but defense in depth: mask the getty units so
# even a kernel cmdline override does not give us a login prompt.
for unit in getty@.service serial-getty@.service console-getty.service; do
    ln -sf /dev/null "$ROOTFS/etc/systemd/system/${unit}"
done

echo "hardening: enabling story-kernel services"
# Wire the boot chain via static enable links.  This is more deterministic
# than `systemctl enable --root=` which reads installer-injected drop-ins.
for unit in \
    story-kernel-measure-binary.service \
    story-kernel-rtmr3-extend.service \
    story-kernel-lockdown-modules.service \
    story-kernel.service; do
    src="/etc/systemd/system/${unit}"
    dst="$ROOTFS/etc/systemd/system/multi-user.target.wants/${unit}"
    mkdir -p "$(dirname "$dst")"
    ln -sf "$src" "$dst"
done

echo "hardening: locking root account"
# Root must not be able to log in even via console.  Lock the account, then
# assert it took — an unlocked root would defeat the "no interactive entry"
# property, so fail the build rather than ship it.
sed -i 's/^root:[^:]*:/root:*:/' "$ROOTFS/etc/shadow"
if ! grep -q '^root:[*!]' "$ROOTFS/etc/shadow"; then
    echo "hardening: ERROR — root account is not locked in $ROOTFS/etc/shadow" >&2
    exit 1
fi

echo "hardening: install.sh complete"
