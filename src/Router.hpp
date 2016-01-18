#ifndef DPA_SSL_SNI_FORWARDER_ROUTER
#define DPA_SSL_SNI_FORWARDER_ROUTER

#include <vector>
#include <string>
#include "utils.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

class Host;
class Router {
  struct Destination {
    AddressInfo address;
    std::vector<std::string> SSL_names;
  };
  private:
    std::vector<Destination> destination_list;
  public:
    bool has_default_destination;
    AddressInfo default_destination;
    void add( const AddressInfo& address, const std::vector<std::string>& SSL_names );
    bool search( AddressInfo& result, const std::string& SSL_name );
};

}}

#endif