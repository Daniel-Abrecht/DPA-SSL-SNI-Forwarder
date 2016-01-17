#ifndef DPA_SSL_SNI_FORWARDER_UTILS
#define DPA_SSL_SNI_FORWARDER_UTILS

#include <algorithm>

namespace DPA {
namespace SSL_SNI_Forwarder {


template <typename T>
static inline bool compare_ignore_case( T a, T b ){
  return std::tolower(a) == std::tolower(b);
}

template <typename T>
static inline bool equals_ignore_case( std::basic_string<T> const& a, std::basic_string<T> const& b ){
  if( a.size() != b.size() )
    return false;
  return std::equal( b.begin(), b.end(), a.begin(), compare_ignore_case<T> );
}

template <typename T>
static inline bool less_ignore_case( std::basic_string<T> const& a, std::basic_string<T> const& b ){
  size_t min = std::min( a.size(), b.size() );
  for( size_t i=0; i<min; i++ ){
    if( a[i] != b[i] )
      return a[i] < b[i];
  }
  return a.size() < b.size();
}

struct AddressInfo {
  std::string service = "443";
  std::string node;
  bool operator==(const AddressInfo&) const;
  bool operator<(const AddressInfo&) const;
};

}}

#endif
