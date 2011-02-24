#!/usr/bin/env perl

use 5.008001;

use strict;
use warnings;

# Son, when you participate in sporting events,
# it's not whether you win or lose, it's how drunk you get.
use ExtUtils::MakeMaker;

if ($^O eq 'MSWin32') {
    die "Building on OS '$^O' is unsupported. Only *nix systems\n";
}

WriteMakefile(
    NAME         => 'MojoX::Ping',
    VERSION_FROM => 'lib/MojoX/Ping.pm',
    AUTHOR       => 'Sergey Zasenko <d3fin3@gmail.com>',
    PREREQ_PM    => {
        'Mojolicious' => 0.999942,
        'IO::Poll'    => 0,
    },
    test => {TESTS => 't/*.t t/*/*.t t/*/*/*.t'}
);
