#!/usr/bin/env perl

use strict;
use warnings;

use Test::More;
use Mojo::IOLoop;

plan skip_all => 'You can run tests just as root' if $<;

plan tests => 3;

use_ok 'MojoX::Ping';

my $ping = new_ok 'MojoX::Ping' => [timeout => 1];

my $result;

$ping->ping('127.0.0.1', 1,
    sub {
        my ($ping, $lres) = @_;

        $result = $lres;

        $ping->ioloop->stop;
    }
);

$ping->ioloop->start;

is_deeply $result, [['OK', $result->[0][1]]], 'ping 127.0.0.1';
