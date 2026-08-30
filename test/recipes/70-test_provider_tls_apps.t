#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IPC::Open3;
use Symbol qw(gensym);
use OpenSSL::Test qw/:DEFAULT bldtop_dir bldtop_file data_file srctop_file/;
use OpenSSL::Test::Utils;

setup("test_provider_tls_apps");

plan skip_all => "module support is disabled" if disabled("module");
plan skip_all => "TLS 1.3 is disabled" if disabled("tls1_3");
plan skip_all => "sockets are disabled" if disabled("sock");
plan skip_all => "no TLS 1.3 key exchange is available"
    if disabled("ec") && disabled("dh");
plan skip_all => "not supported on this platform"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

my $suite = "TLS_TEST_PROVIDER_AES_128_GCM_SHA256";
my $shlib_wrap = bldtop_file("util", "wrap.pl");
my $openssl = bldtop_file("apps", "openssl");
my $server_pem = srctop_file("apps", "server.pem");

$ENV{OPENSSL_MODULES} = bldtop_dir("test");
$ENV{OPENSSL_CONF} = data_file("ssl.cnf");

plan tests => 2;

my $ciphers_ok;
my @ciphers = run(app(["openssl", "ciphers", "-s", "-v", "-tls1_3"]),
    capture => 1, statusvar => \$ciphers_ok);
ok($ciphers_ok && grep(/\Q$suite\E/, @ciphers),
   "configuration loads the provider ciphersuite");

sub provider_handshake
{
    my ($server_pid, $client_pid, $server_in, $server_out, $server_err,
        $client_in, $client_out, $client_err);
    my ($port, $client_text, $client_status, $server_status);
    my $ok = 0;

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm 60;

        $server_err = gensym();
        $server_pid = open3($server_in, $server_out, $server_err,
            $shlib_wrap, $openssl, "s_server", "-accept", "0", "-naccept",
            "1", "-cert", $server_pem, "-tls1_3", "-www");
        while (<$server_out>) {
            if (/^ACCEPT \S*:(\d+)/) {
                $port = $1;
                last;
            }
        }
        die "server did not report a port\n" unless defined $port;

        $client_err = gensym();
        $client_pid = open3($client_in, $client_out, $client_err,
            $shlib_wrap, $openssl, "s_client", "-connect",
            "localhost:$port", "-tls1_3", "-brief");
        print $client_in "GET / HTTP/1.0\r\n\r\n";
        close $client_in;
        $client_text = join("", <$client_out>, <$client_err>);
        waitpid($client_pid, 0);
        $client_status = $?;
        waitpid($server_pid, 0);
        $server_status = $?;

        alarm 0;
        $ok = $client_status == 0 && $server_status == 0
            && $client_text =~ /\Q$suite\E/;
    };
    alarm 0;
    if ($@) {
        kill "TERM", $client_pid if defined $client_pid && kill 0, $client_pid;
        kill "TERM", $server_pid if defined $server_pid && kill 0, $server_pid;
        waitpid($client_pid, 0) if defined $client_pid;
        waitpid($server_pid, 0) if defined $server_pid;
    }
    return $ok;
}

ok(provider_handshake(), "s_client and s_server negotiate the provider suite");
