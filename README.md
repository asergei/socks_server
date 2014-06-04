Non-blocking SOCKS5 proxy server
-----------------
### SYNOPSIS

`socks_server.pl --host 127.0.0.1 --port 5000 --logfile proxy.log --loglevel 1`

### DESCRIPTION

`socks_server.pl` is a simple socks5 proxy server. It is non-blocking
which means it can serve multiple clients in a single process simultaneously.

`socks_server.pl` supports a limited subset of socks5 protocol. BIND, UDP
associate and authorization are not supported.

### ARGUMENTS

* --host
Binds to TCP interface. Defaults to 127.0.0.1

* --port
Binds to a TCP port. Defaults to 5000. 

* --logfile
Specifies a path to a logfile.

* --loglevel
Specifies the type of events to be logged. The following values
can be used:

|Loglevel|  Description            |
|--------|-------------------------|
|1       |  error                  |
|2       |  note (including error) |
|3       |  trace (including note) |

Specifying `1` will log only errors. Specifying `2` will log errors and
notes and so on.

### SECURITY

`socks_server.pl` does not implement any security measures like hostname/IP
filtering or authorization.

### LICENSE

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.


