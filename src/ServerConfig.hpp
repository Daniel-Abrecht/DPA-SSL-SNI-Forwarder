#ifndef DPA_SSL_SNI_FORWARDER_CONFIG
#define DPA_SSL_SNI_FORWARDER_CONFIG

#include <map>
#include <string>
#include <vector>
#include "utils.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

  struct ServerConfig {
    bool has_default_destination;
    AddressInfo default_destination;
    std::vector<std::string> route_name_list;
  };

  struct Config {
    std::map<AddressInfo,ServerConfig> server;
    std::map<std::string,std::map<AddressInfo,std::vector<std::string>>> route;
  };

  bool parseConfig( Config& result, const char* path );

}}

#endif