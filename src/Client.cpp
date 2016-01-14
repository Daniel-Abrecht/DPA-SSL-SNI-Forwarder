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

  typedef uint32_t SessionID;
  typedef uint16_t CipherSuite;

  struct __attribute__((packed)) ClientHello {
    struct ProtocolVersion version;
    struct Random random;
    SessionID session_id;
  };

  struct __attribute__((packed)) Handshake {
    uint8_t type;    /* handshake type */
    uint8_t length[3]; /* bytes in message */
    union __attribute__((packed)) {
      ClientHello client_hello;
    };
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
  
  void Client::process(){
    int res = recv( socket, buffer+offset, sizeof(buffer)-offset, 0 );
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
    std::cout << "TLSPlaintext | SSL Version "
      << (unsigned)tls->version.major << "." << (unsigned)tls->version.minor
    << " | length: " << len << std::endl;
    size_t index = sizeof(struct TLSPlaintext);
    bool complete = ( offset - index >= len );
    uint16_t available = std::min( (size_t)len, offset - index );
    
    do {
      if( available < sizeof(struct ClientHello) )
        break;

      struct Handshake* handshake = (struct Handshake*)( buffer + index );
      uint32_t hlen = ( handshake->length[0] << 16 )
                    | ( handshake->length[1] <<  8 )
                    | ( handshake->length[2] <<  0 );

      available -= sizeof(handshake);
      available = std::min( (uint32_t)available, hlen );
      
      std::cout << "Handshake | Type "
        << (unsigned)handshake->type << " | length " << hlen
      << std::endl;
      
      if( handshake->type != HT_client_hello ){
        close();
        return;
      }

//      << (unsigned)hello->version.major << "." << (unsigned)hello->version.minor
//    << " | session id: " << hello->session_id << std::endl;

    } while(0);

    if( complete ){
      close();
      return;
    } return;
  }

  void Client::close(){
    server->remove( this );
  }

}}