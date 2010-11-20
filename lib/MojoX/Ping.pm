package MojoX::Ping;

use strict;
use warnings;

our $VERSION = 0.1;
use base 'Mojo::Base';

use Mojo::IOLoop;
use Socket qw/SOCK_RAW/;
use Time::HiRes 'time';

__PACKAGE__->attr(ioloop => sub { Mojo::IOLoop->singleton });
__PACKAGE__->attr(timeout => 5);
__PACKAGE__->attr('error');

my $ICMP_PING = 'ccnnnA*';

sub ping {
    my ($self, $host, $times, $cb) = @_;

    my $request = {host => $host, times => $times, results => [], cb => $cb};

    my $socket = $self->ioloop->connect(
        address => $host,
        port    => 0,
        args    => {
            Proto => 'icmp',
            Type  => SOCK_RAW
        },
        on_connect => sub {
            my ($loop, $id) = @_;

            $self->_send_request($request);
        },
        on_read => sub {
            my ($loop, $id, $chunk) = @_;

            my $icmp_msg = substr $chunk, 20;

            my ($type, $sequence, $data) =
              (unpack $ICMP_PING, $icmp_msg)[0, 4, 5];

            if ($type == 0) {

                # ICMP ECHO REPLY

                # Is sequence right?
                if ($sequence == @{$request->{results}} + 1) {

                    # Check data
                    if ($data eq $request->{data}) {
                        $self->_store_result($request, 'OK');
                    }
                    else {
                        $self->_store_result($request, 'MALFORMED');
                    }
                }
            }
        },
        on_error => sub {
            my ($loop, $id, $error) = @_;

            $self->error("Unable to create icmp socket : $!");
            $self->_store_result($request, 'ERROR');
        }
    );

    $request->{socket} = $socket;
}

sub _store_result {
    my ($self, $request, $result) = @_;

    my $results = $request->{results};

    # Clear request specific data
    $self->ioloop->drop($request->{timer}) if $request->{timer};
    delete $request->{timer};

    push @$results, [$result, time - $request->{start}];
    if (@$results == $request->{times} || $result eq 'ERROR') {
        # Drop socket
        $self->ioloop->drop($request->{socket}) if $request->{socket};

        # Testing done
        $request->{cb}->($self, $results);
    } else {
        $self->_send_request($request);
    }
}

sub _send_request {
    my ($self, $request) = @_;

    my $checksum   = 0x0000;
    my $identifier = 1;
    my $sequence   = @{$request->{results}} + 1;
    my $data       = 'abcdef';

    my $msg = pack $ICMP_PING,
      0x08, 0x00, $checksum,
      $identifier, $sequence, $data;

    $checksum = $self->_icmp_checksum($msg);

    $msg = pack $ICMP_PING,
      0x08, 0x00, $checksum,
      $identifier, $sequence, $data;

    $request->{data} = $data;

    $request->{start} = time;

    $request->{timer} = $self->ioloop->timer(
        $self->timeout => sub {
            my ($loop) = @_;
            $self->_store_result($request, 'TIMEOUT');
        }
    );

    $self->ioloop->write($request->{socket} => $msg);
}

sub _icmp_checksum {
    my ($self, $msg) = @_;

    my $res = 0;
    foreach my $int (unpack "n*", $msg) {
        $res += $int;
    }

    # Add possible odd byte
    $res += unpack('C', substr($msg, -1, 1)) << 8
      if length($msg) % 2;

    # Fold high into low
    $res = ($res >> 16) + ($res & 0xffff);

    # Two times
    $res = ($res >> 16) + ($res & 0xffff);

    return ~$res;
}

1;
__END__

=head1 NAME

L<MojoX::Ping> - asynchronous ping with L<Mojolicious>.

=head1 SYNOPSIS

    use MojoX::Ping;

    my $ping = MojoX::Ping->new;

    $ping->ping('google.com', 1, sub {
        my ($ping, $result) = @_;
        print "Result: ", $result->[0][0], " in ", $result->[0][1], " seconds\n";
        $ping->ioloop->stop;
    });

    $ping->ioloop->start;

=head1 DESCRIPTION

L<MojoX::Ping> is an asynchronous ping for Mojo.

=head1 SEE ALSO

L<Mojolicious>, L<Mojo::IOLoop>

=head1 AUTHOR

Sergey Zasenko, C<undef@cpan.org>.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010, Sergey Zasenko

This program is free software, you can redistribute it and/or modify it under
the terms of the Artistic License version 2.0.

=cut
