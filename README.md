# DPA-SSL-SNI-Forwarder

A Server which forwards incomming SSL Connections. This project is still incomplete and shouldn't be
used in a production environment.

## How it works

This server doesn't decrypt any ssl traffic; it will just parses the SSL ClientHello until it finds
the first extension from type server_name, it recived the full ClientHello or its buffer is full.
It uses the server name to find out to which server it sould forward the connection, connects to
the server and forwards the whole traffic from both connections to the other connection unmodified. 

## Config file

The usual config file location is /etc/DPA/SSL_SNI_Forwarder.yaml, but you can
also pass the config file location as the first argument. The config file could look as follows:

```
server:
  0.0.0.0 8443:
    route:
      - public
    default: example.net

  localhost 9443:
    route:
      - private
    default: example.net 443

route:
  public:
    destination: example.com 443
    host:
      - example.net
      - example.org

  private:
    destination: example.org
    host:
      - localhost
```
However, i will probably change this a bit soon.

## How to Build

1) make sure you have installed the yaml-cpp library:
https://github.com/jbeder/yaml-cpp

2) Navigate into the source directory, and type:
```make clean all```

## Signals

SIGINT and SIGTERM:
-  The Programm will close all sockets and terminate normally if it recives the SIGINT or SIGTERM signal.

SIGHUP:
 - It will reload the configuration if it recives the SIGHUP signal, all connections related to a listening address which
is removed from the config file will be closed and any other connection will remain unaffected.
