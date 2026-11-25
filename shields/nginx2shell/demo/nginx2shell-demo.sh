#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# usage: nginx2shell-demo.sh install <archive> | start | stop | remove
#                            | reload | status | logs
#                            | master <vulnerable|patched>
#                            | workers <vulnerable|patched>
#
# Runs the two nginx instances of build.sh's image on a Shirudo target,
# as root, in a chroot under /var/lib/nginx2shell-demo (N2S_ROOT):
#
#   https://127.0.0.1:8443  nginx 1.31.8, vulnerable range
#   https://127.0.0.1:9443  nginx 1.31.9, fixed
#
# A target runs no Docker, so this does what Shirudo's
# upatches/app-sandbox/demo/apache.sh does for Apache. install unpacks the
# archive and hard-links three of its files into the target's own tree,
# where the shield looks for them. A hard link is the same inode, so a
# policy label the load sets on /usr/sbin/nginx is on the file the chroot
# executes, and a uprobe on /usr/lib/libssl.so.3 fires in the library
# the chroot's nginx maps:
#
#   <root>/usr/sbin/nginx        -> /usr/sbin/nginx         (1.31.8)
#   <root>/usr/local/sbin/nginx  -> /usr/local/sbin/nginx   (1.31.9)
#   <root>/usr/lib/libssl.so.3   -> $N2S_LIBSSL
#
# N2S_LIBSSL, /usr/lib/libssl.so.3 by default, is the path the h2guard
# upatch was built to probe. On a glibc distribution that path is unused
# (its libssl lives under /usr/lib/<triplet>/); install refuses to replace
# a file that is already there. Load the shield after install: a file
# that appears after a load is not labeled until the next load.

set -eu

root=${N2S_ROOT:-/var/lib/nginx2shell-demo}
libssl=${N2S_LIBSSL:-/usr/lib/libssl.so.3}

usage()
{
	echo "usage: $0 install <archive> | start | stop | remove | reload | status | logs | master <vulnerable|patched> | workers <vulnerable|patched>" >&2
	exit 2
}

die()
{
	echo "$0: $*" >&2
	exit 1
}

links()
{
	printf '%s %s\n' \
		usr/sbin/nginx /usr/sbin/nginx \
		usr/local/sbin/nginx /usr/local/sbin/nginx \
		usr/lib/libssl.so.3 "$libssl"
}

master()
{
	cat "$root/run/n2s-$1.pid" 2>/dev/null || :
}

# The worker PIDs of instance $1, one per line, sorted.
workers()
{
	m=$(master "$1")
	[ -n "$m" ] || return 0
	for status in /proc/[0-9]*/status; do
		awk -v m="$m" '$1 == "PPid:" && $2 == m { split(FILENAME, p, "/"); print p[3] }' \
			"$status" 2>/dev/null
	done | sort -n
}

listening()
{
	python3 - "$1" <<-\EOT
	import socket, sys
	try:
	    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1).close()
	except OSError:
	    sys.exit(1)
	EOT
}

stop()
{
	[ -x "$root/usr/local/bin/n2s-run" ] || return 0
	if [ -n "$(master vulnerable)$(master patched)" ]; then
		chroot "$root" /usr/local/bin/n2s-run stop || :
		for _ in $(seq 50); do
			[ -z "$(master vulnerable)$(master patched)" ] && break
			sleep 0.1
		done
	fi
}

unmount()
{
	for dir in proc dev tmp run; do
		umount -l "$root/$dir" 2>/dev/null || :
	done
}

[ $# -ge 1 ] || usage
case $1 in
install)
	[ $# -eq 2 ] || usage
	[ -s "$2" ] || die "no archive at $2"
	stop
	unmount
	links | while read -r src dst; do
		[ -e "$root/$src" ] && [ "$dst" -ef "$root/$src" ] && rm -f "$dst"
		:
	done
	rm -rf "$root"
	mkdir -p "$root"
	links | while read -r src dst; do
		[ ! -e "$dst" ] ||
			die "$dst exists and is not this demo's; refusing to replace it"
	done
	tar -xf "$2" -C "$root" --exclude='dev/*'
	links | while read -r src dst; do
		mkdir -p "$(dirname "$dst")"
		ln "$root/$src" "$dst" ||
			die "cannot hard-link $root/$src to $dst (same file system needed)"
	done
	echo "nginx2shell demo installed in $root; libssl for the shield: $libssl"
	;;
start)
	[ -x "$root/usr/local/bin/n2s-run" ] || die "not installed; run $0 install <archive>"
	stop
	unmount
	mkdir -p "$root/run" "$root/tmp" "$root/proc" "$root/dev"
	mount -t tmpfs tmpfs "$root/run"
	mount -t tmpfs tmpfs "$root/tmp"
	chmod 1777 "$root/tmp"
	mount -t proc proc "$root/proc"
	mount --bind /dev "$root/dev"
	chroot "$root" /usr/local/bin/n2s-run start
	for _ in $(seq 50); do
		if listening 8443 && listening 9443; then
			echo "nginx 1.31.8 on https://127.0.0.1:8443, nginx 1.31.9 on https://127.0.0.1:9443"
			exit 0
		fi
		sleep 0.2
	done
	die "nginx does not answer; see $root/var/log/nginx/"
	;;
stop)
	stop
	unmount
	;;
remove)
	stop
	unmount
	if [ -d "$root" ]; then
		links | while read -r src dst; do
			[ -e "$root/$src" ] && [ "$dst" -ef "$root/$src" ] && rm -f "$dst"
			:
		done
	fi
	rm -rf "$root"
	;;
status)
	for i in vulnerable patched; do
		printf '%s master=%s workers=%s\n' "$i" "$(master "$i")" \
			"$(workers "$i" | paste -sd, -)"
	done
	;;
reload)
	# A HUP: each master forks fresh workers and the old ones finish what
	# they serve. Returns once both instances run no worker of before.
	[ -x "$root/usr/local/bin/n2s-run" ] || die "not installed; run $0 install <archive>"
	old=$(workers vulnerable; workers patched)
	chroot "$root" /usr/local/bin/n2s-run reload
	for _ in $(seq 100); do
		now=" $( (workers vulnerable; workers patched) | tr '\n' ' ') "
		stale=0
		for pid in $old; do
			case $now in
			*" $pid "*) stale=1 ;;
			esac
		done
		if [ "$stale" -eq 0 ] && [ -n "$(workers vulnerable)" ] &&
			[ -n "$(workers patched)" ]; then
			echo "reloaded: vulnerable=$(workers vulnerable | paste -sd, -) patched=$(workers patched | paste -sd, -)"
			exit 0
		fi
		sleep 0.1
	done
	die "the reload did not replace every worker within 10 s"
	;;
master)
	[ $# -eq 2 ] || usage
	master "$2"
	;;
workers)
	[ $# -eq 2 ] || usage
	workers "$2"
	;;
logs)
	for f in "$root"/var/log/nginx/n2s-*.error.log; do
		[ -f "$f" ] || continue
		echo "== $f"
		cat "$f"
	done
	;;
*)
	usage
	;;
esac
