#include <iostream>
#include <exception>
#include <cstring>

#include <signal.h>
#include <unistd.h>

#include  "ServerManager.hpp"

using namespace DPA::SSL_SNI_Forwarder;

static ServerManager* servermanager = 0;

void intHandler( int dummy ){
  (void)dummy;
  if( servermanager )
    servermanager->stop();
}

int main( int argc, const char *argv[] ){
  if( argc > 2 || ( argc == 2 && (
      !strcmp(argv[1],"help")
   || !strcmp(argv[1],"--help")
   || !strcmp(argv[1],"-h")
  ))){
    std::cout << "Usage: " << argv[0] << " [config file]" << std::endl;
    return 0;
  }

  std::cout << "Start" << std::endl;

  ServerManager servermanager;

  // Close standard input
  close( STDIN_FILENO );

  // Setup signal handlers
  signal( SIGINT , intHandler );
  signal( SIGTERM, intHandler );
  signal( SIGHUP, [](int dummy){
    (void) dummy;
    if(::servermanager)
      ::servermanager->do_reload = true;
  });

  // Set config file
  if( argc == 2 )
    servermanager.setConfigFile( argv[1] );

  // Load config file
  servermanager.reloadConfig();

  ::servermanager = &servermanager;

  // Start server
  servermanager.run();

  std::cout << "end" << std::endl;

  ::servermanager = 0;
  return 0;
}
