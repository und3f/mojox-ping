package MojoX::Ping;

use strict;
use warnings;

our $VERSION = 0.2;
use base 'Mojo::Base';

use Mojo::IOLoop;
use Socket qw/SOCK_RAW/;
use Time::HiRes 'time';
use IO::Socket::INET qw/sockaddr_in inet_aton/;
use IO::Poll qw/POLLIN POLLOUT/;
use Carp qw/croak/;

__PACKAGE__->attr(ioloop => sub { Mojo::IOLoop->singleton });
__PACKAGE__->attr(interval => 0.2);
__PACKAGE__->attr(timeout  => 5);
__PACKAGE__->attr('error');

my $ICMP_PING = 'ccnnnA*';

my $ICMP_ECHOREPLY     = 0;     # Echo Reply
my $ICMP_DEST_UNREACH  = 3;     # Destination Unreachable
my $ICMP_SOURCE_QUENCH = 4;     # Source Quench
my $ICMP_REDIRECT      = 5;     # Redirect (change route)
my $ICMP_ECHO          = 8;     # Echo Request
my $ICMP_TIME_EXCEEDED = 11;    # Time Exceeded

sub ping {
    my ($self, $host, $times, $cb) = @_;

    my $socket =
      IO::Socket::INET->new(Proto => 'icmp', Type => SOCK_RAW, Blocking => 0)
      or croak "Unable to create icmp socket : $!";

    my $poll = IO::Poll->new;

    $poll->mask($socket => POLLOUT);

    my $ip = inet_aton($host);

    my $request = {
        host        => $host,
        times       => $times,
        results     => [],
        cb          => $cb,
        poll        => $poll,
        socket      => $socket,
        identifier  => int(rand 0x10000),
        destination => scalar sockaddr_in(0, $ip)
    };

    $self->ioloop->on_tick(sub { $self->_run_poll($poll, $request) });

    return $self;
}

sub start {
    my ($self) = @_;
    $self->ioloop->start;

    return $self;
}

sub _run_poll {
    my ($self, $poll, $request) = @_;

    $poll->poll(0);

    if ($poll->handles(POLLOUT)) {
        $self->_send_request($request);
    }
    elsif ($poll->handles(POLLIN)) {
        $self->_on_read($request);
    }
}

sub _on_read {
    my ($self, $request) = @_;

    $request->{socket}->sysread(my $chunk, 4194304, 0);

    my $icmp_msg = substr $chunk, 20;

    my ($type, $identifier, $sequence, $data);

    $type = unpack 'c', $icmp_msg;

    if ($type == $ICMP_ECHOREPLY) {
        ($type, $identifier, $sequence, $data) =
          (unpack $ICMP_PING, $icmp_msg)[0, 3, 4, 5];
    }
    elsif ($type == $ICMP_DEST_UNREACH || $type == $ICMP_TIME_EXCEEDED) {
        ($identifier, $sequence) = unpack('nn', substr($chunk, 52));
    }
    else {

        # Don't mind
        return;
    }

    # Is it response to our latest message?
    return unless $identifier == $request->{identifier};
    return unless $sequence == @{$request->{results}} + 1;

    if ($type == $ICMP_ECHOREPLY) {

        # Check data
        if ($data eq $request->{data}) {
            $self->_store_result($request, 'OK');
        }
        else {
            $self->_store_result($request, 'MALFORMED');
        }
    }
    elsif ($type == $ICMP_DEST_UNREACH) {
        $self->_store_result($request, 'DEST_UNREACH');
    }
    elsif ($type == $ICMP_TIME_EXCEEDED) {
        $self->_store_result($request, 'TIMEOUT');
    }
}

sub _store_result {
    my ($self, $request, $result) = @_;

    my $results = $request->{results};

    # Clear request specific data
    $self->ioloop->drop($request->{timer}) if $request->{timer};
    delete $request->{timer};

    push @$results, [$result, time - $request->{start}];

    if (@$results == $request->{times} || $result eq 'ERROR') {

        # Testing done
        $request->{cb}->($self, $results);
    }

    # Perform another check
    else {

        my $socket = $request->{socket};
        $request->{poll}->mask($socket);

        # Setup interval timer before next request
        $self->ioloop->timer(
            $self->interval => sub {
                $request->{poll}->mask($socket, POLLOUT);
            }
        );
    }
}

sub _send_request {
    my ($self, $request) = @_;

    my $checksum   = 0x0000;
    my $identifier = $request->{identifier};
    my $sequence   = @{$request->{results}} + 1;
    my $data       = 'abcdef';

    my $msg = pack $ICMP_PING,
      $ICMP_ECHO, 0x00, $checksum,
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

    my $socket = $request->{socket};

    $socket->send($msg, 0, $request->{destination}) or die "$!";

    $request->{poll}->mask($socket, POLLIN);
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

    # Run this code as root
    use MojoX::Ping;

    my $ping = MojoX::Ping->new;

    $ping->ping('google.com', 1, sub {
        my ($ping, $result) = @_;
        print "Result: ", $result->[0][0],
          " in ", $result->[0][1], " seconds\n";
        $ping->ioloop->stop;
    })->start;

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
