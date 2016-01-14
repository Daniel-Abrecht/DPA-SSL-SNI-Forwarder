#include <iostream>
#include <signal.h>

#include  "Server.hpp"

#define RW_BUFFER_SIZE 1024 * 4

//static char buffer[RW_BUFFER_SIZE];

using namespace DPA::SSL_SNI_Forwarder;

static Server* server = 0;

void intHandler( int dummy ){
  (void)dummy;
  if( server )
    server->stop();
}

int main(){

  std::cout << "Starting server" << std::endl;

  signal( SIGINT , intHandler );
  signal( SIGTERM, intHandler );

  Server server( "0.0.0.0", "8443" );
  if( !server.isOK() ){
    std::cerr << "Error: " << server.getLastError() << std::endl;
    return 1;
  }

  ::server = &server;

  std::cout << "Server running"  << std::endl;
  server.run();

  std::cout << "Stoping server"  << std::endl;

  return 0;
}
