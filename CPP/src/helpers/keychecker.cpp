#include <pagmo/types.hpp>
#include <vector>

unsigned int count_equal_bits(const pagmo::vector_double k, std::vector<std::byte> c){
  unsigned int count = 0;
  for(int i = 0; i<k.size(); i++){
    unsigned char n = char(k[i]) & char(c[i]);
    while(n){
      count += n & 1;
      n = n>>1;
    }
    n = ~char(k[i]) & ~char(c[i]);
    while(n){
      count += n & 1;
      n = n>>1;
    }
  }
  return count;
}
