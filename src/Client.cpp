#include <errno.h>
#include <unistd.h>
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>
#include <sys/sendfile.h>

#include "Server.hpp"
#include "Client.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

  Client::Client(
    Server* server,
    int socket,
    struct sockaddr_storage& address,
    socklen_t address_length
  ) : server(server)
    , socket(socket)
    , address(address)
    , address_length(address_length)
  {}

  Client::~Client(){
    if( socket != -1 )
      ::close( socket );
    if( destination != -1 )
      ::close( destination );
    server->remove( this );
  }

  void Client::addToSet( fd_set& read_set, fd_set& write_set, int& maxfd ){
    if( read_or_write ){
      if(socket)
        FD_SET( socket, &read_set );
      if( socket > maxfd )
        maxfd = socket;
      if(destination)
        FD_SET( destination, &read_set );
      if( destination > maxfd )
        maxfd = destination;
    }else{
      if( source_or_destination ){
        if(socket)
          FD_SET( socket, &write_set );
        if( socket > maxfd )
          maxfd = socket;
      }else{
        if(destination)
          FD_SET( destination, &write_set );
        if( destination > maxfd )
          maxfd = destination;
      }
    }
  }

  enum ContentType {
    CT_change_cipher_spec = 20,
    CT_alert = 21,
    CT_handshake = 22,
    CT_application_data = 23
  };

  struct __attribute__((packed)) ProtocolVersion {
    uint8_t major;
    uint8_t minor;
  };

  struct __attribute__((packed)) TLSPlaintext {
    uint8_t type;
    struct ProtocolVersion version;
    uint16_t length;
  };

  struct __attribute__((packed)) Random {
    uint32_t gmt_unix_time;
    char random_bytes[28];
  };

  typedef uint16_t CipherSuite;
  typedef uint8_t CompressionMethod;

  struct __attribute__((packed)) ClientHello {
    struct ProtocolVersion version;
    struct Random random;
  };

  struct __attribute__((packed)) Handshake {
    uint8_t type;    /* handshake type */
    uint8_t length[3]; /* bytes in message */
    ClientHello client_hello;
  };

  enum HandshakeType {
    HT_hello_request,
    HT_client_hello,
    HT_server_hello,
    HT_certificate = 11,
    HT_server_key_exchange,
    HT_certificate_request,
    HT_server_hello_done,
    HT_certificate_verify,
    HT_client_key_exchange,
    HT_finished = 20
  };

  enum ExtensionType {
    ET_SSL_SNI
  };
 
  struct __attribute__((packed)) Extension {
    uint16_t type;
    uint16_t length;
  };

  struct __attribute__((packed)) ServerName {
    uint8_t type;
    uint16_t length;
  };

  void Client::process( fd_set& read_set, fd_set& write_set ){
    if( read_or_write ){
      if( (source_or_destination ? socket : destination) == -1
        || !FD_ISSET( source_or_destination ? socket : destination, &read_set )
      ){
        source_or_destination = !source_or_destination;
        if( (source_or_destination ? socket : destination) == -1
          || !FD_ISSET( source_or_destination ? socket : destination, &read_set )
        ){
          source_or_destination = !source_or_destination;
          return;
        }
      }
    }else{
      if( !FD_ISSET( source_or_destination ? socket : destination, &write_set ) )
        return;
    }
    (this->*next_action)();
  }

  void Client::determinateDestination(){
    int res = recv( socket, buffer+write_offset, buffer_size-write_offset, 0 );
    if( res == -1 ){
      const char* msg = strerror(errno);
      std::cerr << "Error: " << msg << std::endl;
      close();
      return;
    }
    if( !res ){
      close();
      return;
    }
    write_offset += res;
    if( write_offset < sizeof(struct TLSPlaintext) )
      return; // not enough data
    struct TLSPlaintext* tls = (struct TLSPlaintext*)buffer;
    if( tls->type != CT_handshake ){
      close();
      return;
    }
    uint16_t len = ntohs( tls->length );
    std::cout << "TLSPlaintext | length: " << len << std::endl;
    size_t index = sizeof(struct TLSPlaintext);
    bool complete = ( write_offset - index >= len || len > buffer_size );
    uint16_t available = std::min( (size_t)len, write_offset - index ) + index;

    do {
      if( available - index <= sizeof(struct Handshake) )
        break;

      struct Handshake* handshake = (struct Handshake*)( buffer + index );
      uint32_t hlen = ( handshake->length[0] << 16 )
                    | ( handshake->length[1] <<  8 )
                    | ( handshake->length[2] <<  0 );

      index += sizeof(struct Handshake);
      if( available - index >= hlen ){
        available = hlen;
        complete = true;
      }

      std::cout << "Handshake | Type "
        << (unsigned)handshake->type << " | length " << hlen
      << std::endl;
      if( handshake->type != HT_client_hello ){
        close();
        return;
      }

      std::cout << "ClientHello | SSL Version "
        << (unsigned)handshake->client_hello.version.major << "."
        << (unsigned)handshake->client_hello.version.minor
      << std::endl;

      if( index + 6 >= available )
        break;

      index += buffer[index] + 1;

      if( index + 5 >= available )
        break;

      uint16_t ciphersuite_size = ( buffer[index  ] << 8 )
                                | ( buffer[index+1] << 0 );
      std::cout << "Ciphersuites size: " << ciphersuite_size << std::endl;
      index += 2 + ciphersuite_size;
      if( index + 3 >= available )
        break;

      uint8_t compression_method_size = buffer[index];
      std::cout << "Compressions method size: " << (unsigned)compression_method_size << std::endl;
      index += 1 + compression_method_size;
      if( index + 2 >= available )
        break;

      uint16_t extension_size = ( buffer[index  ] << 8 )
                              | ( buffer[index+1] << 0 );
      std::cout << "Extensions size: " << extension_size << std::endl;
      index += 2;
      if( extension_size > available - index )
        extension_size = available - index;

      std::cout << "Searching SNI extension..." << std::endl;

      while( extension_size >= sizeof(Extension) ){
        Extension* e = (Extension*)(buffer+index);
        extension_size -= sizeof(Extension);
        index += sizeof(Extension);
        uint16_t length = ntohs(e->length);
        uint16_t type = ntohs(e->type);
        std::cout << "Extension length: " << length
        << " | type: " << type << std::endl;
        if( length > extension_size )
          break;
        if( type == ET_SSL_SNI ){
          if( length <= 5 )
            break;
          uint16_t e_len = (buffer[index]<<8) | buffer[index+1];
          int i = index + 2;
          if( e_len > length-2 )
            break;
          while( e_len ){
            uint8_t type = buffer[i++];
            uint16_t b_len = (buffer[i]<<8) | buffer[i+1];
            i += 2;
            if( e_len < b_len + 2 )
              break;
            e_len -= b_len + 2;
            if( b_len ){
              serverNameList.push_back({
                (ServerNameType)type,
                std::string((char*)buffer+i,b_len)
              });
            }
            i += b_len;
          }
          break;
        }
        index += length;
        extension_size -= length;
      }

    } while(0);

    if( complete || !serverNameList.empty() ){
      Client::lookupDestinationAddress();
      return;
    }

  }

  void Client::lookupDestinationAddress(){

    bool found = false;
    if( serverNameList.empty() ){
      std::cout << "Servername not found" << std::endl;
    }else{
      std::cout << serverNameList.size() << " servernames found, search destination: " << std::endl;
      for( auto& name : serverNameList ){
        std::cout << " * for servername " << name.name << std::endl;
        if(( found = server->router.search( destination_address, name.name ) ))
          break;
      }
    }
    if( found ){
      std::cout << "Destination found: ";
    }else if( server->router.has_default_destination ){
      destination_address = server->router.default_destination;
      std::cout << "Using default destination: ";
    }else{
      std::cout << "No destination found" << std::endl;
      close();
      return;
    }
    std::cout << "node " << destination_address.node << " service " <<  destination_address.service << std::endl;

    struct addrinfo hints;
    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;  /* Datagram socket */
    int eno = getaddrinfo( destination_address.node.c_str(), destination_address.service.c_str(), &hints, &address_results );
    if( eno ){
      std::cerr << "getaddrinfo failed: " << gai_strerror( eno ) << std::endl;
      close();
      return;
    }

    addr = address_results;
    Client::connect();

  }

  void Client::connect(){
    read_or_write = false;
    source_or_destination = false;
    next_action = &Client::connect;

    if( destination != -1 ){
      int so_error;
      socklen_t slen = sizeof( so_error );
      getsockopt( destination, SOL_SOCKET, SO_ERROR, &so_error, &slen );
      if( !so_error ){
        std::cout << "Connected " << socket << " <==> " << destination << std::endl;
        next_action = &Client::send;
        return;
      }
      if( so_error == EINPROGRESS )
        return;
      std::cerr << "Async connect failed: " << strerror( so_error ) << std::endl;
      ::close( destination );
      destination = -1;
    }

    for( ; addr; addr = addr->ai_next ){
      destination = ::socket( addr->ai_family, addr->ai_socktype | SOCK_NONBLOCK, addr->ai_protocol );
      if( destination == -1 )
        continue;
      int res;
      char node[256], service[256];
      if( !getnameinfo( addr->ai_addr, addr->ai_addrlen, node, sizeof(node), service, sizeof(service), NI_NUMERICSERV ) )
        std::cout << "Try to connect to addr " << destination_address.node << " service " << destination_address.service << std::endl;
      do {
        res = ::connect( destination, addr->ai_addr, addr->ai_addrlen );
      } while( res == -1 && errno == EINTR );
      if( res == -1 ){
        if( errno == EINPROGRESS )
          return;
        std::cerr << "Connect failed: " << strerror( errno ) << std::endl;
      }
      if( !res ) break;
      ::close( destination );
      destination = -1;
    }

    if( address_results )
      freeaddrinfo( address_results );

    if( !addr ){
      std::cerr << "No address_result found for " << destination_address.node << " service " << destination_address.service << std::endl;
      close();
      return;
    }else{
      std::cout << "Connected " << socket << " <==> " << destination << std::endl;
      next_action = &Client::send;
      return;
    }

  }


  void Client::send(){
    if(!write_offset)
      goto allSent;
    {
//      std::cout << "Send data, " << read_offset << " - " << write_offset << " bytes" << std::endl;
      ssize_t res;
      do {
        res = ::send( source_or_destination ? socket : destination, buffer+read_offset, write_offset-read_offset, 0 );
      } while( res == -1 && errno == EINVAL );
      if( res == -1 ){
        std::cerr << "Send failed: " << strerror(errno) << std::endl;
        return;
      }
//      std::cout << "Sent " << res << " bytes" << std::endl;
      read_offset += res;
      if( read_offset >= write_offset )
        goto allSent;
      return;
    }
    allSent: {
      read_offset = 0;
      write_offset = 0;
      read_or_write = true;
      next_action = &Client::recive;
      return;
    }
  }

  void Client::recive(){
    ssize_t res;
    do {
      res = recv( source_or_destination ? socket : destination, buffer, buffer_size, 0 );
    } while( res == -1 && errno == EINVAL );
    if( res >= 0 || ( res == -1 && ( errno != EAGAIN || errno != EWOULDBLOCK ) ) ){
      if( res == -1 ){
        std::cerr << "Recv error: " << strerror(errno) << std::endl;
        close();
        return;
      }
      if( !res ){
        close();
        return;
      }
      write_offset = res;
//      std::cout << "recived " << res << " bytes of data" << std::endl;
      read_or_write = false;
      source_or_destination = !source_or_destination;
      next_action = &Client::send;
    }
  }

  void Client::close(){
    delete this;
  }

}}
