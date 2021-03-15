#include <string>
#include <map>
#include <pagmo/types.hpp>
#include <set>
#include "crypto_functions.h"
#include <iostream>

double chi_squared(int length, std::map<char,int> monograms, std::map<std::string,int> digrams);

double index_of_coincidence(long int n, std::map<char,int> monograms){
  double sum=0;
  for(auto i : monograms){
    sum+=i.second*(i.second-1);
  }
  return abs(sum*10000/(n*(n-1))-686);
}
double ensure_unique_numbers(const pagmo::vector_double &dv){
  std::set<int> s;
  int count=0;
  for(auto i : dv){
    s.insert((int)i);
    count++;
  }
  return count-s.size();
}

double evaluate(std::string plaintext){
  //std::cout << "Evaluating: " << plaintext << std::endl;
  return chi_squared(plaintext.size(),get_monogram_frequencies(plaintext),get_digram_frequencies(plaintext));
  return index_of_coincidence(plaintext.size(),get_monogram_frequencies(plaintext));
}

struct msub_generic {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 26;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      (0.1+evaluate(substitute(ciphertext,dv)))*ensure_unique_numbers(dv)
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      {0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.},
      {25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.},
    };
  }
};

struct vigenere_generic {
  std::string ciphertext;
  int key_length;
  pagmo::vector_double::size_type get_nix() const{
    return 5;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(vigenere_decrypt(ciphertext,dv,key_length))
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      {0.,0.,0.,0.,0.},
      {25.,25.,25.,25.,25.},
    };
  }
};

struct playfair_generic {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 25;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(playfair_decrypt(ciphertext,dv))
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      {0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.},
      {25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.,25.},
    };
  }
};

struct des_generic {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 8;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(des_decrypt(dv,ciphertext))
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      {0.,0.,0.,0.,0.,0.,0.,0.},
      {255.,255.,255.,255.,255.,255.,255.,255.},
    };
  }
};

struct rsa_factor {
};

struct aes_generic {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 16;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(aes_decrypt(dv,ciphertext))
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      {0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.},
      {255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.},
    };
  }
};

struct speck_generic {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 16;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(speck_decrypt(dv,ciphertext))
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      {0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.},
      {255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.,255.},
    };
  }
};
