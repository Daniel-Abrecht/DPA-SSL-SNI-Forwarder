#include <errno.h>
#include <cstring>

#include <map>
#include <string>
#include <utility>
#include <iostream>

#include "Host.hpp"
#include "Server.hpp"
#include "ServerManager.hpp"
#include "ServerConfig.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

void ServerManager::run(){

  fd_set set;
  struct timeval tv;

  while( keep_running ){
    if(do_reload){
      reloadConfig();
      do_reload = false;
    }

    int maxfd = 0;
    FD_ZERO( &set );

    for( auto server : server_list )
      server->addToSet( set, maxfd );

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    int n = select( maxfd+1, &set, 0, 0, &tv );
    if( !n )
      continue;
    if( n == -1 ){
      std::cerr << "Error: " << strerror( errno ) << std::endl;
      continue;
    }

    for( auto server : server_list )
      server->process( set );

  }

}

void ServerManager::stop(){
  keep_running = false;
}

void ServerManager::setConfigFile( const char* file ){
  config_file = file;
}

bool ServerManager::reloadConfig(){

  std::cout << "Reloading config file" << std::endl;

  Config config;
  if( !parseConfig( config, config_file ) ){
    std::cout << "Failed to reload config file" << std::endl;
    return false;
  }

  std::cout << "Config file loaded, applying new configuration" << std::endl;

  // Find existing servers which have an entry in the config file
  std::map<ServerConfig*,Server*> servers;
  for( auto server : server_list ){
    auto result = config.server.find( server->getAddress() );
    if( result == config.server.end() ){
      delete server;
    }else{
      servers[&result->second] = server;
    }
  }

  server_list.clear();

  // Reconfigure / Create new servers
  for( auto& sconf : config.server ){
    Server* s;
    ServerConfig* c = &sconf.second;
    auto result = servers.find( c );
    if( result == servers.end() ){
      s = new Server( sconf.first );
      servers[c] = s;
    }else{
      s = result->second;
    }

    // Update routes

    s->router->clear();
    if( c->has_default_destination ){
      s->router->default_destination = std::shared_ptr<Host>(new Host(c->default_destination));
    }else{
      s->router->default_destination = std::nullptr_t();
    }

    for( auto name : c->route_name_list ){
      auto result = config.route.find(name);
      if( result == config.route.end() ){
        std::cerr << "No route entry for " << name << " found" << std::endl;
        continue;
      }
      auto& route = result->second;
      s->router->add( route.destination, route.host );
    }

    server_list.push_back(s);
  }

  return true;
}


}}
