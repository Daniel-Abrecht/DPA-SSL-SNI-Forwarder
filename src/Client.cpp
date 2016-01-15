#include <errno.h>
#include <iostream>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>

#include "Server.hpp"
#include "Client.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

  Client::Client(
    Server* server,
    int socket,
    struct sockaddr_storage address,
    socklen_t address_length
  ) : server(server)
    , socket(socket)
    , address(address)
    , address_length(address_length)
    , offset(0)
  {}

  Client::~Client(){
    ::close( socket );
  }

  void Client::addToSet( fd_set& set, int& maxfd ){
    FD_SET( socket, &set );
    maxfd = maxfd > socket ? maxfd : socket;
  }

  bool Client::isSet( fd_set& set ){
    return FD_ISSET( socket, &set );
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
  
  void Client::process(){
    int res = recv( socket, buffer+offset, buffer_size-offset, 0 );
    if( res < 0 ){
      const char* msg = strerror(errno);
      std::cerr << "Error: " << msg << std::endl;
      return;
    }
    if( !res ){
      close();
      return;
    }
    offset += res;
    if( offset < sizeof(struct TLSPlaintext) )
      return; // not enough data
    struct TLSPlaintext* tls = (struct TLSPlaintext*)buffer;
    if( tls->type != CT_handshake ){
      close();
      return;
    }
    uint16_t len = ntohs( tls->length );
    std::cout << "TLSPlaintext | length: " << len << std::endl;
    size_t index = sizeof(struct TLSPlaintext);
    bool complete = ( offset - index >= len || len > buffer_size );
    uint16_t available = std::min( (size_t)len, offset - index ) + index;
    
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
              serverNameList.push_back( ServerNameEntry(
                (ServerNameType)type, std::string((char*)buffer+i,b_len)
              ));
            }
            i += b_len;
          }
          break;
        }
        index += length;
        extension_size -= length;
      }

    } while(0);
    
    if( serverNameList.size() ){
      std::cout << serverNameList.size() << " servernames found:" << std::endl;
      for( auto name : serverNameList ){
        std::cout << " * type: " << name.type
          << " | value: " << name.name
        << std::endl;
      }
      return;
    }

    if( complete ){
      std::cout << "Servername not found" << std::endl;
      close();
      return;
    } return;
  }

  void Client::close(){
    server->remove( this );
  }

}}