#include <iostream>
#include <cstring>
#include "Host.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

  Host::Host( const std::string& name, const std::string& protocol )
   : name(name)
   , protocol( protocol )
  {}

  Host::~Host(){
  }

  int Host::connect(){

    struct addrinfo* address_results = 0;
    struct addrinfo* address = 0;

    std::cout << "Update addrinfo for " << name << std::endl;

    struct addrinfo hints;
    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;  /* Datagram socket */
    int eno = getaddrinfo( name.c_str(), protocol.c_str(), &hints, &address_results );
    if( eno ){
      std::cerr << "getaddrinfo failed: " << gai_strerror( eno ) << std::endl;
      return -1;
    }

    int socket = -1;
    for( address = address_results; address; address = address->ai_next ){
      socket = ::socket( address->ai_family, address->ai_socktype, address->ai_protocol );
      if( socket == -1 )
        continue;
      int res;
      char node[256], service[256];
      if( !getnameinfo( address->ai_addr, address->ai_addrlen, node, sizeof(node), service, sizeof(service), NI_NUMERICSERV ) )
        std::cout << "Try to connect to address " << node << " port " << service << std::endl;
      do {
        res = ::connect( socket, address->ai_addr, address->ai_addrlen );
      } while( res == -1 && errno == EINTR );
      if( res == -1 )
        std::cerr << "Connect failed: " << strerror( errno ) << std::endl;
      if( !res )
        break;
      close( socket );
      socket = -1;
    }

    if( address_results )
      freeaddrinfo( address_results );

    if( !address ){
      std::cerr << "No address_result found for " << std::endl;
      return -1;
    }

    return socket;
  }

}}
