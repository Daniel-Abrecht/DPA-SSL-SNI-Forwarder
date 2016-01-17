#include <iostream>
#include <yaml-cpp/yaml.h>
#include "utils.hpp"
#include "ServerConfig.hpp"

namespace YAML {

using namespace DPA::SSL_SNI_Forwarder;

template<typename T>
static inline void parse( T& x, const Node& node ){
  x = node.as<T>();
}

template<>
struct convert<AddressInfo> {
  static Node encode(const AddressInfo& ai) {
    Node node;
    node = ai.node + " " + ai.service;
    return node;
  }

  static bool decode(const Node& node, AddressInfo& ai) {
    std::string listen_addr = node.as<std::string>();
    size_t pos = listen_addr.find_last_of(' ');
    if( pos == std::string::npos ){
      ai.service = "443";
      ai.node = listen_addr;
    }else{
      ai.service    = listen_addr.substr( pos + 1 );
      while( pos && listen_addr[pos-1] == ' ' )
        pos--;
      ai.node = listen_addr.substr( 0, pos );
    }
    return true;
  }
};

template<>
struct convert<ServerConfig> {
  static Node encode(const ServerConfig& sc) {
    Node node;
    node["route"  ] = sc.route_name_list;
    if(sc.has_default_destination)
      node["default"] = sc.default_destination;
    return node;
  }

  static bool decode(const Node& node, ServerConfig& sc) {
    parse( sc.route_name_list, node["route"] );
    sc.has_default_destination = node["default"];
    if(sc.has_default_destination)
      parse( sc.default_destination, node["default"] );
    return true;
  }
};

template<>
struct convert<RouteConfig> {
  static Node encode(const RouteConfig& rc) {
    Node node;
    node["destination"] = rc.destination;
    node["host"] = rc.host;
    return node;
  }

  static bool decode(const Node& node, RouteConfig& rc) {
    parse( rc.destination, node["destination"] );
    parse( rc.host, node["host"] );
    return true;
  }
};

template<>
struct convert<Config> {

  static Node encode(const Config& rc) {
    Node node;
    node["server"] = rc.server;
    node["route"] = rc.route;
    return node;
  }

  static bool decode(const Node& node, Config& config) {
    if( node["server"] )
      parse( config.server, node["server"] );
    if( node["route" ] )
      parse( config.route , node["route" ] );
    return true;
  }

};

}

namespace DPA {
namespace SSL_SNI_Forwarder {

bool AddressInfo::operator==(const AddressInfo& b) const {
  return equals_ignore_case( node, b.node )
      && equals_ignore_case( service, b.service );
}

bool AddressInfo::operator<(const AddressInfo& b) const {
  if( equals_ignore_case( service, b.service ) )
    return less_ignore_case( node , b.node );
  return less_ignore_case( service, b.service );
}


bool parseConfig( Config& result, const char* config_file ){
  YAML::Node config;

  try {
    config = YAML::LoadFile( config_file );
  } catch( YAML::BadFile& e ){
    std::cerr << "YAML::LoadFile failed: YAML::BadFile: " << e.what() << std::endl;
    std::cerr << "Pleas check if the file " << config_file << " exists. " << std::endl;
    return false;
  } catch( std::exception& e ){
    std::cerr << "YAML::LoadFile failed: " << e.what() << std::endl;
    return false;
  }

  try {
    result = config.as<Config>();
  } catch( std::exception& e ){
    std::cerr << "Failed to parse configuration: " << e.what() << std::endl;
    return false;
  }

  return true;
}

}}

