#include <string>
#include <cstddef>
#include "Router.hpp"
#include "utils.hpp"

namespace DPA {
namespace SSL_SNI_Forwarder {

void Router::add(
  const AddressInfo& address,
  const std::vector<std::string>& SSL_names
){
  for( auto& destination : destination_list )
    if( destination.address == address ){
      destination.SSL_names = SSL_names;
    }
  destination_list.push_back( { address, SSL_names } );
}

bool Router::search( AddressInfo& result, const std::string& SSL_name ){
  for( auto& destination : destination_list )
    for( auto& name : destination.SSL_names )
      if( equals_ignore_case( name, SSL_name ) ){
        result = destination.address;
        return true;
      }
  return false;
}

}}
