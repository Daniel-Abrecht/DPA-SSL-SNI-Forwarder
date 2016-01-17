#include <iostream>
#include <cstring>
#include "Host.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

  Host::Host( const AddressInfo& address )
   : address(address)
  {}

  Host::~Host(){
  }

  int Host::connect(){

    struct addrinfo* address_results = 0;
    struct addrinfo* addr = 0;

    struct addrinfo hints;
    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;  /* Datagram socket */
    int eno = getaddrinfo( address.node.c_str(), address.service.c_str(), &hints, &address_results );
    if( eno ){
      std::cerr << "getaddrinfo failed: " << gai_strerror( eno ) << std::endl;
      return -1;
    }

    int socket = -1;
    for( addr = address_results; addr; addr = addr->ai_next ){
      socket = ::socket( addr->ai_family, addr->ai_socktype, addr->ai_protocol );
      if( socket == -1 )
        continue;
      int res;
      char node[256], service[256];
      if( !getnameinfo( addr->ai_addr, addr->ai_addrlen, node, sizeof(node), service, sizeof(service), NI_NUMERICSERV ) )
        std::cout << "Try to connect to addr " << node << " port " << service << std::endl;
      do {
        res = ::connect( socket, addr->ai_addr, addr->ai_addrlen );
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

    if( !addr ){
      std::cerr << "No address_result found for " << std::endl;
      return -1;
    }

    return socket;
  }

}}
