#include <iostream>
#include <errno.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include  "Server.hpp"
#include  "Router.hpp"
#include  "Client.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

  Server::Server(
    const char* addr,
    const char* port,
    std::shared_ptr<Router> router
  ) : router(router) {
    struct addrinfo hints;
    memset( &hints, 0, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;  /* Datagram socket */
    int eno = getaddrinfo( addr, port, &hints, &address_results );
    if( eno ){
      error = gai_strerror( eno );
      return;
    }
    for( address_result = address_results; address_result; address_result = address_result->ai_next ){
      socket = ::socket( address_result->ai_family, address_result->ai_socktype, address_result->ai_protocol );
      if( socket == -1 )
        continue;
      int res;
      char node[256], service[256];
      if( !getnameinfo( address_result->ai_addr, address_result->ai_addrlen, node, sizeof(node), service, sizeof(service), NI_NUMERICSERV ) )
        std::cout << "Try to bind to address " << node << " port " << service << std::endl;
      do {
        res = bind( socket, address_result->ai_addr, address_result->ai_addrlen );
      } while( res == -1 && errno == EINTR );
      if( !res )
        break;
      if( res == -1 )
        std::cerr << "Bind failed: " << strerror( errno ) << std::endl;
      close( socket );
      socket = -1;
    }
    if( !address_result ){
      error = "No address_result found";
      return;
    }
    if( listen( socket, 10 ) == -1 ){
      error = strerror( errno );
      return;
    }
    valid = true;
  }

  Server::~Server(){
    if( socket != -1 )
      close( socket );
    if( address_results )
      freeaddrinfo( address_results );
  }

  void Server::run(){

    if(!valid)
      return;

    fd_set set;
    struct timeval tv;

    keep_running = true;

    while( keep_running ){

      maxfd = socket;

      FD_ZERO( &set );
      FD_SET( socket, &set );

      for( auto client : clients )
        client->addToSet( set, maxfd );

      tv.tv_sec = 5;
      tv.tv_usec = 0;
      int n = select( maxfd+1, &set, 0, 0, &tv );
      if( !n )
        continue;
      if( n == -1 ){
        error = strerror( errno );
        std::cerr << "Error: " << error << std::endl;
        continue;
      }

      if( FD_ISSET( socket, &set ) )
        if( acceptClient() )
          std::cout << "New connection" << std::endl;

      for( auto client : clients )
        client->process( set );

    }

  }

  bool Server::acceptClient(){
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    int fd = accept( socket, (struct sockaddr*)&addr, &len );
    if( fd == -1 ){
      error = strerror(errno);
      std::cerr << "Error: " << error << std::endl;
      return false;
    }
    if( len > sizeof(addr) )
      std::cerr << "Notice: Address too big" << std::endl;
    Client* client = new Client( this, fd, addr, len );
    clients.push_back( client );
    return true;
  }

  bool Server::isOK(){
    return valid;
  }

  const char* Server::getLastError(){
    return error;
  }

  void Server::stop(){
    keep_running = false;
  }

  void Server::remove( Client* c ){
    std::cout << "Remove connection" << std::endl;
    for( std::vector<Client*>::iterator client = clients.begin(); client != clients.end(); ++client )
      if( *client == c ){
        clients.erase( client );
        break;
      }
    delete c;
  }

}}
