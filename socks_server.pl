#!/usr/bin/perl
use common::sense;
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use Getopt::Long;

$| = 1;

my $listen_host = '127.0.0.1';
my $listen_port = 5000;
my %log_level = (
    error   => 1,
    note    => 2,
    trace   => 3,
);
my $log_level;
my $log_filepath = 'proxy.log';
my $need_help;

GetOptions(
    'host=s'        => \$listen_host,
    'port=i'        => \$listen_port,
    'logfile=s'     => \$log_filepath,
    'loglevel=i'    => \$log_level,
    'help'          => \$need_help,
) or print_usage();

print_usage() if $need_help;

# ==============================================================================

my $fh_log;
if ($log_level) {
    open $fh_log, '>:encoding(utf8)', $log_filepath or die $!;
}

print "Server started\n";

my $active_count;
my $conn_count;
tcp_server $listen_host, $listen_port, sub {
    my ($fh, $host, $port) = @_;
    
    my $conn_id = ++$conn_count;
    $active_count++;
    
    my $log = $log_level
        ? sub {
            my ($level, @rest) = @_;
            _log($level, $conn_id, $active_count, $host, $port, @rest);
        }
        : sub {};
    
    $log->(note => 'New client');
    
    my $client; $client = AnyEvent::Handle->new(
        fh          => $fh,
        keepalive   => 1,
        on_error    => sub {
            my ($client, $fatal, $message) = @_;
            $active_count--;
            $log->(error => $fatal && "(fatal)", $message);
            $client->destroy;
        },
        on_eof      => sub {
            $active_count--;
            $log->(note => 'client disconnected');
            $client->destroy;
        },
    );
    
# ==============================================================================
    
    my $handle_connect = AE::cv(sub {
        my ($type, $dst, $address, $port) = eval { shift->recv };
        unless ($dst and $address and $type and $port and !$@) {
            $log->(error => "Missing paramters", $type, $dst, $address, $port, $@);
            $client->push_write("\x05\xff");
            $client->push_shutdown;
            return 1;
        }
    
        $log->(note => "Proxy to: $address : $port");
        
        my $remote; $remote = AnyEvent::Handle->new(
            connect     => [$address, $port],
            on_read     => sub {
                $log->(trace => "Remote read", $_[0]{rbuf});
                $client->push_write($_[0]{rbuf});
                $_[0]{rbuf} = '';
            },
            on_eof      => sub {
                shift->destroy;
                $client->destroy;
                $active_count--;
                $log->(trace => "Remote disconnected on eof");
            },
            on_error    => sub {
                my ($remote, $fatal, $message) = @_;
                $remote->destroy;
                $active_count--;
                $log->(error => "Remote error", $fatal && '(fatal)', $message);
                $client->destroy;
            },
            on_connect => sub {
                $client->push_write(pack("C*", 5, 0, 0, $type) . $dst);
            },
        );
        $client->on_read(sub {
            $log->(trace => "Client read", $_[0]{rbuf});
            $remote->push_write($_[0]{rbuf});
            $_[0]{rbuf} = '';
        });
    });
    
# ==============================================================================

    # get Version and length of the Method field
    $client->unshift_read(chunk => 2, sub {
        my ($client, $chunk) = @_;
        my ($version, $method_len) = unpack 'C*', $chunk;
        
        $log->(trace => "Step 1", unpack 'H*', $chunk);
        
        # wrong version
        unless ($version == 5) {
            $client->push_write("\x05\xff");
            $client->push_shutdown;
            return 1;
        }

        # get Method (can be multiple methods)
        $client->unshift_read(chunk => $method_len, sub {
            my ($client, $chunk) = @_;
            
            $log->(trace => "Step 2", unpack 'C*', $chunk);
            
            my %methods = map { $_ => 1 } unpack 'C*', $chunk;
            
            # no authentication
            unless (exists $methods{0}) {
               $client->push_write("\x05\xff");
               $client->push_shutdown;
               return 1;
            }
            
            $client->push_write("\x05\x00"); # proceed
            $client->unshift_read(chunk => 4, sub {
                my ($client, $chunk) = @_;

                $log->(trace => "Step 3", unpack 'C*', $chunk);

                my ($ver, $cmd, $atyp) = unpack 'CCxC', $chunk;
                
                unless ($ver == 5 and $cmd == 1) {
                    $client->push_write("\x05\xff");
                    $client->push_shutdown;
                    return 1;
                }

                if ($atyp == 1) { # ipv4
                    $client->unshift_read(chunk => 4 + 2, sub {
                        my $host = join '.', unpack "C*", substr($_[1], 0, 4);
                        my $port = unpack 'n', substr($_[1], 4, 2);
                        $log->(trace => "Step 4 (ipv4)", "$host:$port");
                        $handle_connect->send($atyp, $_[1], $host, $port);
                        return 1;
                    });
                } elsif ($atyp == 3) { # hostname
                    $client->unshift_read(chunk => 1, sub {
                        my $len_raw = $_[1];
                        my $len = unpack 'C', $len_raw;
                        $client->unshift_read(chunk => $len + 2, sub {
                            $log->(trace => "Step 4 (hostname)", unpack "A${len}n", $_[1]);
                            $handle_connect->send($atyp, $len_raw . $_[1], unpack "A${len}n", $_[1]);
                            return 1;
                        });
                        return 1;
                    });
                } elsif ($atyp == 4) { # ipv6
                    $client->unshift_read(chunk => 16 + 2, sub {
                        $handle_connect->send($atyp, $_[1], unpack "b16n", $_[1]); # XXX: TODO
                        return 1;
                    });
                } else {
                    $client->push_write("\x05\xff");
                    $client->push_shutdown;
                    return 1;
                }
                return 1;
            });
            return 1;
        });
        return 1;
    });
};


AnyEvent->condvar->recv;


sub print_usage {
    require Pod::Usage;
    Pod::Usage::pod2usage(-verbose => 1);
}

sub _log {
    my ($level, $conn_id, $active_id, $ip, $port, @rest) = @_;
    return unless $log_level and $log_level{$level}
        and $log_level{$level} <= $log_level;
        
    my @lt = reverse((localtime)[0..5]);
    $lt[0] += 1900;
    print $fh_log sprintf "[%04d-%02d-%02d %02d:%02d:%02d][%d][%04d][%s:%d] %s: %s\n",
        @lt, $conn_id, $active_id, $ip, $port, $level, join '; ', @rest;
}


__END__

=pod

=head1 NAME

socks_server.pl - Socks5 proxy server

=head1 SYNOPSIS

  socks_server.pl --host 127.0.0.1 --port 5000 --logfile proxy.log --loglevel 1

=head1 DESCRIPTION

C<socks_server.pl> is a simple socks5 proxy server. It is non-blocking
which means it can serve multiple clients in a single process simultaneously.

C<socks_server.pl> supports a limited subset of socks5 protocol. BIND, UDP
associate and authorization are not supported.

=head1 ARGUMENTS

=over 4

=item --host

Binds to TCP interface. Defaults to 127.0.0.1

=item --port

Binds to a TCP port. Defaults to 5000. 

=item --logfile

Specifies a path to a logfile.

=item --loglevel

Specifies the type of events to be logged. The following values
can be used:

   Loglevel  Description 
   1         error  
   2         note (including error)
   3         trace (including note)

Specifying C<1> will log only errors. Specifying C<2> will log errors and
notes and so on.

=back

=head1 SECURITY

C<socks_server.pl> does not implement any security measures like hostname/IP
filtering or authorization.

=head1 SEE ALSO

L<http://www.ietf.org/rfc/rfc1928.txt>

=head1 AUTHOR

 <asergei@gmail.com>

=head1 LICENSE

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut

