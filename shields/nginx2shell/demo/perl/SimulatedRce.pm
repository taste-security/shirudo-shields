# SPDX-License-Identifier: BSD-2-Clause
#
# SIMULATED post-exploit step, served at /__simulated_rce. It is not an
# exploit and needs none: nginx's embedded Perl runs it in the worker, so
# it does what code an attacker got into a worker would try first, as
# the worker. It runs "/bin/sh -c id" and opens a TCP connection to
# 192.0.2.1:4444 (TEST-NET-1, reserved for documentation, nothing
# listens there), and reports in the response body whether the kernel
# let each happen. The test scenarios and the demo read these lines:
#
#   exec=ok output="uid=101(nginx) ..."   the shell ran
#   exec=refused errno=EACCES             the kernel refused the exec
#   connect=ok | attempted errno=<E>      the kernel let the connect go out
#   connect=refused errno=EPERM           the kernel refused the connect

package SimulatedRce;

use strict;
use warnings;
use nginx;
use Errno ();
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use POSIX ();
use Socket qw(PF_INET SOCK_STREAM SOL_SOCKET SO_ERROR inet_aton sockaddr_in);

my $C2_ADDR = '192.0.2.1';
my $C2_PORT = 4444;

sub errno_name {
	my ($n) = @_;
	local $! = $n;
	for my $name (keys %!) {
		return $name if $!{$name};
	}
	return "errno$n";
}

sub refused {
	my ($name) = @_;
	return $name eq 'EPERM' || $name eq 'EACCES';
}

# fork and exec by hand, so that a refused exec is told apart from a
# shell that ran: the child sends exec's errno back on a pipe that
# closes on a successful exec.
sub try_exec {
	my ($out_r, $out_w, $err_r, $err_w);
	pipe($out_r, $out_w) or return ('error', 'errno=' . errno_name($! + 0));
	pipe($err_r, $err_w) or return ('error', 'errno=' . errno_name($! + 0));
	my $pid = fork();
	return ('error', 'fork errno=' . errno_name($! + 0)) unless defined $pid;
	if ($pid == 0) {
		close $out_r;
		close $err_r;
		open(STDOUT, '>&', $out_w);
		open(STDERR, '>&', $out_w);
		{ no warnings 'exec'; exec { '/bin/sh' } 'sh', '-c', 'id'; }
		syswrite($err_w, pack('N', $! + 0));
		POSIX::_exit(127);
	}
	close $out_w;
	close $err_w;
	my $err = '';
	my $out = '';
	{
		local $/;
		$err = <$err_r> // '';
		$out = <$out_r> // '';
	}
	close $err_r;
	close $out_r;
	waitpid($pid, 0);
	if (length($err) == 4) {
		my $name = errno_name(unpack('N', $err));
		return (refused($name) ? 'refused' : 'error', "errno=$name");
	}
	$out =~ s/\s+$//;
	$out =~ s/"/'/g;
	return ('ok', "output=\"$out\"");
}

sub try_connect {
	my $s;
	unless (socket($s, PF_INET, SOCK_STREAM, 0)) {
		my $name = errno_name($! + 0);
		return (refused($name) ? 'refused' : 'error', "errno=$name socket");
	}
	my $flags = fcntl($s, F_GETFL, 0);
	fcntl($s, F_SETFL, $flags | O_NONBLOCK);
	my $addr = sockaddr_in($C2_PORT, inet_aton($C2_ADDR));
	if (connect($s, $addr)) {
		close $s;
		return ('ok', '');
	}
	my $n = $! + 0;
	if ($!{EINPROGRESS}) {
		my $w = '';
		vec($w, fileno($s), 1) = 1;
		if (select(undef, $w, undef, 2) > 0) {
			$n = unpack('i', getsockopt($s, SOL_SOCKET, SO_ERROR));
			close $s;
			return ('ok', '') if $n == 0;
		} else {
			close $s;
			return ('attempted', 'errno=ETIMEDOUT');
		}
	} else {
		close $s;
	}
	my $name = errno_name($n);
	return (refused($name) ? 'refused' : 'attempted', "errno=$name");
}

sub handler {
	my $r = shift;
	$r->send_http_header('text/plain');
	return OK if $r->header_only;

	my ($exec, $exec_detail) = try_exec();
	my ($conn, $conn_detail) = try_connect();
	my $body = "SIMULATED post-exploit step (no exploit, a test fixture)\n"
		. "worker pid=$$ uid=$< nginx=" . $nginx::VERSION . "\n"
		. "exec=$exec $exec_detail\n"
		. "connect=$conn $conn_detail target=$C2_ADDR:$C2_PORT\n";
	$r->print($body);
	return OK;
}

1;
