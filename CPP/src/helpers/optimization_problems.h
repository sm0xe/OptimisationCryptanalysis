#include <string>
#include <map>
#include <pagmo/types.hpp>
#include <set>
#include "crypto_functions.h"
#include <iostream>

#define PRIME_BASE_SIZE 12

const int rsa_prime_base[PRIME_BASE_SIZE] = {2,3,5,7,11,13,17,19,23,29,31,37};
double chi_squared(int length, std::map<char,int> monograms, std::map<std::string,int> digrams);
double chi_squared_playfair(int length, std::map<char,int> monograms, std::map<std::string,int> digrams);

int4096_t gcd(int4096_t a, int4096_t b){
  if (!a) return b;
  return gcd(b%a,a);
}


double known_plaintext(std::string known, std::string plaintext){
  return plaintext.find(known)==-1;
}

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
  std::string stripped;
  //std::map<char,int> m = get_monogram_frequencies(plaintext);
  //std::map<std::string,int> d = get_digram_frequencies(plaintext);
  int size=0;
  for(auto i : plaintext){
    if((i>='A' && i<='Z') || (i>='a' && i<='z')){
      size+=1;
      stripped+=i;
    }
    /*if(!((i>=' ' && i<='@') || (i>='[' && i<='`') || (i>='{' && i<='~'))){
      size+=1;
    }*/
  }
  std::map<char,int> m = get_monogram_frequencies(stripped);
  std::map<std::string,int> d = get_digram_frequencies(stripped);
  return chi_squared(size,m,d);
  return index_of_coincidence(size,m);
}

double evaluate_playfair(std::string plaintext){
  std::map<char,int> m = get_monogram_frequencies(plaintext);
  std::map<std::string,int> d = get_digram_frequencies(plaintext);
  return chi_squared_playfair(plaintext.size(),m,d);
  return index_of_coincidence(plaintext.size(),m);
}

int4096_t prime_vector_to_int(const pagmo::vector_double &dv,int offset){
  int4096_t x = 1;
  for(int i=0; i<PRIME_BASE_SIZE; i++){
    x=x * (int4096_t)pow(rsa_prime_base[i],dv[i+offset]);
  }
  return x;
}

double rsa_fitness(const pagmo::vector_double &dv, int4096_t n){
  int4096_t x = 1;
  int4096_t y = 1;
  for(int i=0; i<PRIME_BASE_SIZE; i++){
    x=x * (int4096_t)pow(rsa_prime_base[i],2*dv[i]);
    y=y * (int4096_t)pow(rsa_prime_base[i],2*dv[i+PRIME_BASE_SIZE]);
  }
  int4096_t fitness = abs(x-y)%n;
  return (double)fitness;
}

double ensure_sum_inequality(const pagmo::vector_double &dv, int4096_t n){
  int4096_t x = 1;
  int4096_t y = 1;
  for(int i=0; i<PRIME_BASE_SIZE; i++){
    x=x*(int4096_t)pow(rsa_prime_base[i],dv[i]);
    y=y*(int4096_t)pow(rsa_prime_base[i],dv[i+PRIME_BASE_SIZE]);
  }
  return (x+y==n);
}

double ensure_non_trivial(const pagmo::vector_double &dv, int4096_t n){
  int4096_t x = 1;
  int4096_t y = 1;
  for(int i=0; i<PRIME_BASE_SIZE; i++){
    x=x*(int4096_t)pow(rsa_prime_base[i],dv[i]);
    y=y*(int4096_t)pow(rsa_prime_base[i],dv[i+PRIME_BASE_SIZE]);
  }
  return gcd(x+y,n)==1 || gcd(y-x,n)==1;
}


double ensure_inequality(const pagmo::vector_double &dv, int4096_t n){
  int4096_t x = 1;
  int4096_t y = 1;
  bool same=true;
  for(int i=0; i<PRIME_BASE_SIZE; i++){
    if(dv[i]!=dv[i+PRIME_BASE_SIZE]) same=false;
    x=x*(int4096_t)pow(rsa_prime_base[i],dv[i]);
    //if(x>n) return 100000;
    y=y*(int4096_t)pow(rsa_prime_base[i],dv[i+PRIME_BASE_SIZE]);
    //if(y>n) return 200000;
  }
  if(same) return 300000;
  return (double)(y<x);
}

struct shift_generic {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 1;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(substitute(ciphertext,dv)),
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(1,0),pagmo::vector_double(1,25),
    };
  }
};

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
      evaluate(substitute(ciphertext,dv)),
      /*
      double(dv[0]==dv[1] || dv[0]==dv[2] || dv[0]==dv[3] || dv[0]==dv[4] || dv[0]==dv[5] || dv[0]==dv[6] || dv[0]==dv[7] || dv[0]==dv[8] || dv[0]==dv[9] || dv[0]==dv[10] || dv[0]==dv[11] || dv[0]==dv[12] || dv[0]==dv[13] || dv[0]==dv[14] || dv[0]==dv[15] || dv[0]==dv[16] || dv[0]==dv[17] || dv[0]==dv[18] || dv[0]==dv[19] || dv[0]==dv[20] || dv[0]==dv[21] || dv[0]==dv[22] || dv[0]==dv[23] || dv[0]==dv[24] || dv[0]==dv[25]),

      double(dv[1]==dv[2] || dv[1]==dv[3] || dv[1]==dv[4] || dv[1]==dv[5] || dv[1]==dv[6] || dv[1]==dv[7] || dv[1]==dv[8] || dv[1]==dv[9] || dv[1]==dv[10] || dv[1]==dv[11] || dv[1]==dv[12] || dv[1]==dv[13] || dv[1]==dv[14] || dv[1]==dv[15] || dv[1]==dv[16] || dv[1]==dv[17] || dv[1]==dv[18] || dv[1]==dv[19] || dv[1]==dv[20] || dv[1]==dv[21] || dv[1]==dv[22] || dv[1]==dv[23] || dv[1]==dv[24] || dv[1]==dv[25]),

      double(dv[2]==dv[3] || dv[2]==dv[4] || dv[2]==dv[5] || dv[2]==dv[6] || dv[2]==dv[7] || dv[2]==dv[8] || dv[2]==dv[9] || dv[2]==dv[10] || dv[2]==dv[11] || dv[2]==dv[12] || dv[2]==dv[13] || dv[2]==dv[14] || dv[2]==dv[15] || dv[2]==dv[16] || dv[2]==dv[17] || dv[2]==dv[18] || dv[2]==dv[19] || dv[2]==dv[20] || dv[2]==dv[21] || dv[2]==dv[22] || dv[2]==dv[23] || dv[2]==dv[24] || dv[2]==dv[25]),

      double(dv[3]==dv[4] || dv[3]==dv[5] || dv[3]==dv[6] || dv[3]==dv[7] || dv[3]==dv[8] || dv[3]==dv[9] || dv[3]==dv[10] || dv[3]==dv[11] || dv[3]==dv[12] || dv[3]==dv[13] || dv[3]==dv[14] || dv[3]==dv[15] || dv[3]==dv[16] || dv[3]==dv[17] || dv[3]==dv[18] || dv[3]==dv[19] || dv[3]==dv[20] || dv[3]==dv[21] || dv[3]==dv[22] || dv[3]==dv[23] || dv[3]==dv[24] || dv[3]==dv[25]),

      double(dv[4]==dv[5] || dv[4]==dv[6] || dv[4]==dv[7] || dv[4]==dv[8] || dv[4]==dv[9] || dv[4]==dv[10] || dv[4]==dv[11] || dv[4]==dv[12] || dv[4]==dv[13] || dv[4]==dv[14] || dv[4]==dv[15] || dv[4]==dv[16] || dv[4]==dv[17] || dv[4]==dv[18] || dv[4]==dv[19] || dv[4]==dv[20] || dv[4]==dv[21] || dv[4]==dv[22] || dv[4]==dv[23] || dv[4]==dv[24] || dv[4]==dv[25]),

      double(dv[5]==dv[6] || dv[5]==dv[7] || dv[5]==dv[8] || dv[5]==dv[9] || dv[5]==dv[10] || dv[5]==dv[11] || dv[5]==dv[12] || dv[5]==dv[13] || dv[5]==dv[14] || dv[5]==dv[15] || dv[5]==dv[16] || dv[5]==dv[17] || dv[5]==dv[18] || dv[5]==dv[19] || dv[5]==dv[20] || dv[5]==dv[21] || dv[5]==dv[22] || dv[5]==dv[23] || dv[5]==dv[24] || dv[5]==dv[25]),

      double(dv[6]==dv[7] || dv[6]==dv[8] || dv[6]==dv[9] || dv[6]==dv[10] || dv[6]==dv[11] || dv[6]==dv[12] || dv[6]==dv[13] || dv[6]==dv[14] || dv[6]==dv[15] || dv[6]==dv[16] || dv[6]==dv[17] || dv[6]==dv[18] || dv[6]==dv[19] || dv[6]==dv[20] || dv[6]==dv[21] || dv[6]==dv[22] || dv[6]==dv[23] || dv[6]==dv[24] || dv[6]==dv[25]),

      double(dv[7]==dv[8] || dv[7]==dv[9] || dv[7]==dv[10] || dv[7]==dv[11] || dv[7]==dv[12] || dv[7]==dv[13] || dv[7]==dv[14] || dv[7]==dv[15] || dv[7]==dv[16] || dv[7]==dv[17] || dv[7]==dv[18] || dv[7]==dv[19] || dv[7]==dv[20] || dv[7]==dv[21] || dv[7]==dv[22] || dv[7]==dv[23] || dv[7]==dv[24] || dv[7]==dv[25]),

      double(dv[8]==dv[9] || dv[8]==dv[10] || dv[8]==dv[11] || dv[8]==dv[12] || dv[8]==dv[13] || dv[8]==dv[14] || dv[8]==dv[15] || dv[8]==dv[16] || dv[8]==dv[17] || dv[8]==dv[18] || dv[8]==dv[19] || dv[8]==dv[20] || dv[8]==dv[21] || dv[8]==dv[22] || dv[8]==dv[23] || dv[8]==dv[24] || dv[8]==dv[25]),

      double(dv[9]==dv[10] || dv[9]==dv[11] || dv[9]==dv[12] || dv[9]==dv[13] || dv[9]==dv[14] || dv[9]==dv[15] || dv[9]==dv[16] || dv[9]==dv[17] || dv[9]==dv[18] || dv[9]==dv[19] || dv[9]==dv[20] || dv[9]==dv[21] || dv[9]==dv[22] || dv[9]==dv[23] || dv[9]==dv[24] || dv[9]==dv[25]),

      double(dv[10]==dv[11] || dv[10]==dv[12] || dv[10]==dv[13] || dv[10]==dv[14] || dv[10]==dv[15] || dv[10]==dv[16] || dv[10]==dv[17] || dv[10]==dv[18] || dv[10]==dv[19] || dv[10]==dv[20] || dv[10]==dv[21] || dv[10]==dv[22] || dv[10]==dv[23] || dv[10]==dv[24] || dv[10]==dv[25]),

      double(dv[11]==dv[12] || dv[11]==dv[13] || dv[11]==dv[14] || dv[11]==dv[15] || dv[11]==dv[16] || dv[11]==dv[17] || dv[11]==dv[18] || dv[11]==dv[19] || dv[11]==dv[20] || dv[11]==dv[21] || dv[11]==dv[22] || dv[11]==dv[23] || dv[11]==dv[24] || dv[11]==dv[25]),

      double(dv[12]==dv[13] || dv[12]==dv[14] || dv[12]==dv[15] || dv[12]==dv[16] || dv[12]==dv[17] || dv[12]==dv[18] || dv[12]==dv[19] || dv[12]==dv[20] || dv[12]==dv[21] || dv[12]==dv[22] || dv[12]==dv[23] || dv[12]==dv[24] || dv[12]==dv[25]),

      double(dv[13]==dv[14] || dv[13]==dv[15] || dv[13]==dv[16] || dv[13]==dv[17] || dv[13]==dv[18] || dv[13]==dv[19] || dv[13]==dv[20] || dv[13]==dv[21] || dv[13]==dv[22] || dv[13]==dv[23] || dv[13]==dv[24] || dv[13]==dv[25]),

      double(dv[14]==dv[15] || dv[14]==dv[16] || dv[14]==dv[17] || dv[14]==dv[18] || dv[14]==dv[19] || dv[14]==dv[20] || dv[14]==dv[21] || dv[14]==dv[22] || dv[14]==dv[23] || dv[14]==dv[24] || dv[14]==dv[25]),

      double(dv[15]==dv[16] || dv[15]==dv[17] || dv[15]==dv[18] || dv[15]==dv[19] || dv[15]==dv[20] || dv[15]==dv[21] || dv[15]==dv[22] || dv[15]==dv[23] || dv[15]==dv[24] || dv[15]==dv[25]),

      double(dv[16]==dv[17] || dv[16]==dv[18] || dv[16]==dv[19] || dv[16]==dv[20] || dv[16]==dv[21] || dv[16]==dv[22] || dv[16]==dv[23] || dv[16]==dv[24] || dv[16]==dv[25]),

      double(dv[17]==dv[18] || dv[17]==dv[19] || dv[17]==dv[20] || dv[17]==dv[21] || dv[17]==dv[22] || dv[17]==dv[23] || dv[17]==dv[24] || dv[17]==dv[25]),

      double(dv[18]==dv[19] || dv[18]==dv[20] || dv[18]==dv[21] || dv[18]==dv[22] || dv[18]==dv[23] || dv[18]==dv[24] || dv[18]==dv[25]),

      double(dv[19]==dv[20] || dv[19]==dv[21] || dv[19]==dv[22] || dv[19]==dv[23] || dv[19]==dv[24] || dv[19]==dv[25]),

      double(dv[20]==dv[21] || dv[20]==dv[22] || dv[20]==dv[23] || dv[20]==dv[24] || dv[20]==dv[25]),

      double(dv[21]==dv[22] || dv[21]==dv[23] || dv[21]==dv[24] || dv[21]==dv[25]),

      double(dv[22]==dv[23] || dv[22]==dv[24] || dv[22]==dv[25]),

      double(dv[23]==dv[24] || dv[23]==dv[25]),

      double(dv[24]==dv[25])
      */
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(26,0),pagmo::vector_double(26,25),
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
    return 1;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(vigenere_decrypt(ciphertext,dv,key_length)),
      known_plaintext("YEAR",vigenere_decrypt(ciphertext,dv,key_length))
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(key_length,0),pagmo::vector_double(key_length,25),
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
      evaluate_playfair(playfair_decrypt(ciphertext,dv)),
      /*
      double(dv[0]==9 || dv[0]==dv[1] || dv[0]==dv[2] || dv[0]==dv[3] || dv[0]==dv[4] || dv[0]==dv[5] || dv[0]==dv[6] || dv[0]==dv[7] || dv[0]==dv[8] || dv[0]==dv[9] || dv[0]==dv[10] || dv[0]==dv[11] || dv[0]==dv[12] || dv[0]==dv[13] || dv[0]==dv[14] || dv[0]==dv[15] || dv[0]==dv[16] || dv[0]==dv[17] || dv[0]==dv[18] || dv[0]==dv[19] || dv[0]==dv[20] || dv[0]==dv[21] || dv[0]==dv[22] || dv[0]==dv[23] || dv[0]==dv[24]),

      double(dv[1]==9 || dv[1]==dv[2] || dv[1]==dv[3] || dv[1]==dv[4] || dv[1]==dv[5] || dv[1]==dv[6] || dv[1]==dv[7] || dv[1]==dv[8] || dv[1]==dv[9] || dv[1]==dv[10] || dv[1]==dv[11] || dv[1]==dv[12] || dv[1]==dv[13] || dv[1]==dv[14] || dv[1]==dv[15] || dv[1]==dv[16] || dv[1]==dv[17] || dv[1]==dv[18] || dv[1]==dv[19] || dv[1]==dv[20] || dv[1]==dv[21] || dv[1]==dv[22] || dv[1]==dv[23] || dv[1]==dv[24]),

      double(dv[2]==9 || dv[2]==dv[3] || dv[2]==dv[4] || dv[2]==dv[5] || dv[2]==dv[6] || dv[2]==dv[7] || dv[2]==dv[8] || dv[2]==dv[9] || dv[2]==dv[10] || dv[2]==dv[11] || dv[2]==dv[12] || dv[2]==dv[13] || dv[2]==dv[14] || dv[2]==dv[15] || dv[2]==dv[16] || dv[2]==dv[17] || dv[2]==dv[18] || dv[2]==dv[19] || dv[2]==dv[20] || dv[2]==dv[21] || dv[2]==dv[22] || dv[2]==dv[23] || dv[2]==dv[24]),

      double(dv[3]==9 || dv[3]==dv[4] || dv[3]==dv[5] || dv[3]==dv[6] || dv[3]==dv[7] || dv[3]==dv[8] || dv[3]==dv[9] || dv[3]==dv[10] || dv[3]==dv[11] || dv[3]==dv[12] || dv[3]==dv[13] || dv[3]==dv[14] || dv[3]==dv[15] || dv[3]==dv[16] || dv[3]==dv[17] || dv[3]==dv[18] || dv[3]==dv[19] || dv[3]==dv[20] || dv[3]==dv[21] || dv[3]==dv[22] || dv[3]==dv[23] || dv[3]==dv[24]),

      double(dv[4]==9 || dv[4]==dv[5] || dv[4]==dv[6] || dv[4]==dv[7] || dv[4]==dv[8] || dv[4]==dv[9] || dv[4]==dv[10] || dv[4]==dv[11] || dv[4]==dv[12] || dv[4]==dv[13] || dv[4]==dv[14] || dv[4]==dv[15] || dv[4]==dv[16] || dv[4]==dv[17] || dv[4]==dv[18] || dv[4]==dv[19] || dv[4]==dv[20] || dv[4]==dv[21] || dv[4]==dv[22] || dv[4]==dv[23] || dv[4]==dv[24]),

      double(dv[5]==9 || dv[5]==dv[6] || dv[5]==dv[7] || dv[5]==dv[8] || dv[5]==dv[9] || dv[5]==dv[10] || dv[5]==dv[11] || dv[5]==dv[12] || dv[5]==dv[13] || dv[5]==dv[14] || dv[5]==dv[15] || dv[5]==dv[16] || dv[5]==dv[17] || dv[5]==dv[18] || dv[5]==dv[19] || dv[5]==dv[20] || dv[5]==dv[21] || dv[5]==dv[22] || dv[5]==dv[23] || dv[5]==dv[24]),

      double(dv[6]==9 || dv[6]==dv[7] || dv[6]==dv[8] || dv[6]==dv[9] || dv[6]==dv[10] || dv[6]==dv[11] || dv[6]==dv[12] || dv[6]==dv[13] || dv[6]==dv[14] || dv[6]==dv[15] || dv[6]==dv[16] || dv[6]==dv[17] || dv[6]==dv[18] || dv[6]==dv[19] || dv[6]==dv[20] || dv[6]==dv[21] || dv[6]==dv[22] || dv[6]==dv[23] || dv[6]==dv[24]),

      double(dv[7]==9 || dv[7]==dv[8] || dv[7]==dv[9] || dv[7]==dv[10] || dv[7]==dv[11] || dv[7]==dv[12] || dv[7]==dv[13] || dv[7]==dv[14] || dv[7]==dv[15] || dv[7]==dv[16] || dv[7]==dv[17] || dv[7]==dv[18] || dv[7]==dv[19] || dv[7]==dv[20] || dv[7]==dv[21] || dv[7]==dv[22] || dv[7]==dv[23] || dv[7]==dv[24]),

      double(dv[8]==9 || dv[8]==dv[9] || dv[8]==dv[10] || dv[8]==dv[11] || dv[8]==dv[12] || dv[8]==dv[13] || dv[8]==dv[14] || dv[8]==dv[15] || dv[8]==dv[16] || dv[8]==dv[17] || dv[8]==dv[18] || dv[8]==dv[19] || dv[8]==dv[20] || dv[8]==dv[21] || dv[8]==dv[22] || dv[8]==dv[23] || dv[8]==dv[24]),

      double(dv[9]==9 || dv[9]==dv[10] || dv[9]==dv[11] || dv[9]==dv[12] || dv[9]==dv[13] || dv[9]==dv[14] || dv[9]==dv[15] || dv[9]==dv[16] || dv[9]==dv[17] || dv[9]==dv[18] || dv[9]==dv[19] || dv[9]==dv[20] || dv[9]==dv[21] || dv[9]==dv[22] || dv[9]==dv[23] || dv[9]==dv[24]),

      double(dv[10]==9 || dv[10]==dv[11] || dv[10]==dv[12] || dv[10]==dv[13] || dv[10]==dv[14] || dv[10]==dv[15] || dv[10]==dv[16] || dv[10]==dv[17] || dv[10]==dv[18] || dv[10]==dv[19] || dv[10]==dv[20] || dv[10]==dv[21] || dv[10]==dv[22] || dv[10]==dv[23] || dv[10]==dv[24]),

      double(dv[11]==9 || dv[11]==dv[12] || dv[11]==dv[13] || dv[11]==dv[14] || dv[11]==dv[15] || dv[11]==dv[16] || dv[11]==dv[17] || dv[11]==dv[18] || dv[11]==dv[19] || dv[11]==dv[20] || dv[11]==dv[21] || dv[11]==dv[22] || dv[11]==dv[23] || dv[11]==dv[24]),

      double(dv[12]==9 || dv[12]==dv[13] || dv[12]==dv[14] || dv[12]==dv[15] || dv[12]==dv[16] || dv[12]==dv[17] || dv[12]==dv[18] || dv[12]==dv[19] || dv[12]==dv[20] || dv[12]==dv[21] || dv[12]==dv[22] || dv[12]==dv[23] || dv[12]==dv[24]),

      double(dv[13]==9 || dv[13]==dv[14] || dv[13]==dv[15] || dv[13]==dv[16] || dv[13]==dv[17] || dv[13]==dv[18] || dv[13]==dv[19] || dv[13]==dv[20] || dv[13]==dv[21] || dv[13]==dv[22] || dv[13]==dv[23] || dv[13]==dv[24]),

      double(dv[14]==9 || dv[14]==dv[15] || dv[14]==dv[16] || dv[14]==dv[17] || dv[14]==dv[18] || dv[14]==dv[19] || dv[14]==dv[20] || dv[14]==dv[21] || dv[14]==dv[22] || dv[14]==dv[23] || dv[14]==dv[24]),

      double(dv[15]==9 || dv[15]==dv[16] || dv[15]==dv[17] || dv[15]==dv[18] || dv[15]==dv[19] || dv[15]==dv[20] || dv[15]==dv[21] || dv[15]==dv[22] || dv[15]==dv[23] || dv[15]==dv[24]),

      double(dv[16]==9 || dv[16]==dv[17] || dv[16]==dv[18] || dv[16]==dv[19] || dv[16]==dv[20] || dv[16]==dv[21] || dv[16]==dv[22] || dv[16]==dv[23] || dv[16]==dv[24]),

      double(dv[17]==9 || dv[17]==dv[18] || dv[17]==dv[19] || dv[17]==dv[20] || dv[17]==dv[21] || dv[17]==dv[22] || dv[17]==dv[23] || dv[17]==dv[24]),

      double(dv[18]==9 || dv[18]==dv[19] || dv[18]==dv[20] || dv[18]==dv[21] || dv[18]==dv[22] || dv[18]==dv[23] || dv[18]==dv[24]),

      double(dv[19]==9 || dv[19]==dv[20] || dv[19]==dv[21] || dv[19]==dv[22] || dv[19]==dv[23] || dv[19]==dv[24]),

      double(dv[20]==9 || dv[20]==dv[21] || dv[20]==dv[22] || dv[20]==dv[23] || dv[20]==dv[24]),

      double(dv[21]==9 || dv[21]==dv[22] || dv[21]==dv[23] || dv[21]==dv[24]),

      double(dv[22]==9 || dv[22]==dv[23] || dv[22]==dv[24]),

      double(dv[23]==9 || dv[23]==dv[24])
      */

    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(25,0),pagmo::vector_double(25,25),
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
      pagmo::vector_double(8,0),pagmo::vector_double(8,255),
    };
  }
};

struct rsa_factor {
  int4096_t n;
  pagmo::vector_double::size_type get_nix() const{
    return 2*PRIME_BASE_SIZE;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 2;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 2;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      rsa_fitness(dv,n), //objective function
      ensure_sum_inequality(dv,n), //(x+y!=n)
      ensure_non_trivial(dv,n),
      double(prime_vector_to_int(dv,0)-n),
      double(prime_vector_to_int(dv,PRIME_BASE_SIZE)-n),
      //ensure_inequality(dv,n), //inequality constraint (x<y)
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(2*PRIME_BASE_SIZE,0),pagmo::vector_double(2*PRIME_BASE_SIZE,10),
    };
  }
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
      pagmo::vector_double(16,0),pagmo::vector_double(16,255),
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
      pagmo::vector_double(16,0),pagmo::vector_double(16,255),
    };
  }
};
