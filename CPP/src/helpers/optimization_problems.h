#include <string>
#include <map>
#include <pagmo/types.hpp>
#include <set>
#include "crypto_functions.h"
#include <iostream>

#define PRIME_BASE_SIZE 4

const int rsa_prime_base[PRIME_BASE_SIZE] = {2,3,5,7};
double chi_squared(int length, std::map<char,int> monograms, std::map<std::string,int> digrams,std::map<std::string,int> trigrams);
double chi_squared_playfair(int length, std::map<char,int> monograms, std::map<std::string,int> digrams, std::map<std::string,int> trigrams);
double van_vuuren(long int n, std::map<char,int> monograms);

int4096_t gcd(int4096_t a, int4096_t b){
  if (!a) return b;
  return gcd(b%a,a);
}


double known_plaintext(std::string known, std::string plaintext){
  return plaintext.find(known)==-1;
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
  std::map<std::string,int> t = get_trigram_frequencies(stripped);
  //return van_vuuren(size,m);
  return chi_squared(size,m,d,t);
  return index_of_coincidence(size,m);
}

double evaluate_playfair(std::string plaintext){
  std::map<char,int> m = get_monogram_frequencies(plaintext);
  std::map<std::string,int> d = get_digram_frequencies(plaintext);
  std::map<std::string,int> t = get_trigram_frequencies(plaintext);
  //return -van_vuuren(plaintext.size(),m);
  return chi_squared_playfair(plaintext.size(),m,d,t);
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
  int4096_t xx = 1;
  int4096_t yy = 1;
  int4096_t x = 1;
  int4096_t y = 1;
  for(int i=0; i<PRIME_BASE_SIZE; i++){
    xx=xx * (int4096_t)pow(rsa_prime_base[i],2*round(dv[i]));
    yy=yy * (int4096_t)pow(rsa_prime_base[i],2*round(dv[i+PRIME_BASE_SIZE]));
    x=x * (int4096_t)pow(rsa_prime_base[i],round(dv[i]));
    y=y * (int4096_t)pow(rsa_prime_base[i],round(dv[i+PRIME_BASE_SIZE]));
  }
  if(x==1 || y==1) return 1e99;
  if(x==y) return 1e99;
  if(x+y==n) return 1e99;
  int4096_t fitness = abs(xx-yy)%n;
  return (double)fitness;
}

double rsa_fitness_alternative(const pagmo::vector_double &dv, int4096_t n, int4096_t lb, int4096_t ub){
  int4096_t x = 1;
  for(int i=0; i<PRIME_BASE_SIZE; i++){
    x=x * (int4096_t)pow(rsa_prime_base[i],round(dv[i]));
    if(x>ub) return 1e99;
  }
  if(x==1 || x<lb) return 1e99;
  int4096_t fitness = n % x;
  return (double)fitness;
}

double rsa_fitness_houghten_rutkowski(const pagmo::vector_double &dv, int4096_t n){
  int bits = dv.size();
  //int4096_t m = 0;
  int4096_t m = 1<<(bits);
  for(int i=0; i<dv.size(); i++){
    m+=int(round(dv[i]))<<(bits-i-1);
  }
  if(m==0 || m<100) return 1e99;
  int4096_t p = 6*m+1;
  int4096_t q = 6*m-1;
  int4096_t x = n%p;
  int4096_t y = n%q;
  if(x<y) return double(x);
  return double(y);
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

std::string shift_to_msub_key(int n){
  std::string key="";
  for(int i=n; i<26; i++){
    char c = (char)i+'A';
    key+=c;
  }
  for(int i=0; i<n; i++){
    char c = (char)i+'A';
    key+=c;
  }
  return key;
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
      evaluate(substitute(ciphertext,shift_to_msub_key(round(dv[0])))),
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(1,0),pagmo::vector_double(1,25),
    };
  }
};

struct rail_fence_generic {
  std::string ciphertext;
  long unsigned int max_rails;
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
      evaluate(rail_fence_decode(ciphertext,round(dv[0]))),
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(1,2),pagmo::vector_double(1,max_rails),
    };
  }
};

struct columnar_generic {
  std::string ciphertext;
  long unsigned int max_cols;
  pagmo::vector_double::size_type get_nix() const{
    return max_cols;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(columnar_decode(ciphertext,dv)),
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(max_cols,-1),pagmo::vector_double(max_cols,max_cols-1),
    };
  }
};

struct msub_generic {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 26;
  }
  pagmo::vector_double::size_type get_ncx() const{
    return 0;
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
      pagmo::vector_double(26,0),pagmo::vector_double(26,25),
    };
  }
};

struct msub_constrained {
  std::string ciphertext;
  pagmo::vector_double::size_type get_nix() const{
    return 26;
  }
  pagmo::vector_double::size_type get_ncx() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 25;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(substitute(ciphertext,dv)),
      double(round(dv[0])==round(dv[1]) || round(dv[0])==round(dv[2]) || round(dv[0])==round(dv[3]) || round(dv[0])==round(dv[4]) || round(dv[0])==round(dv[5]) || round(dv[0])==round(dv[6]) || round(dv[0])==round(dv[7]) || round(dv[0])==round(dv[8]) || round(dv[0])==round(dv[9]) || round(dv[0])==round(dv[10]) || round(dv[0])==round(dv[11]) || round(dv[0])==round(dv[12]) || round(dv[0])==round(dv[13]) || round(dv[0])==round(dv[14]) || round(dv[0])==round(dv[15]) || round(dv[0])==round(dv[16]) || round(dv[0])==round(dv[17]) || round(dv[0])==round(dv[18]) || round(dv[0])==round(dv[19]) || round(dv[0])==round(dv[20]) || round(dv[0])==round(dv[21]) || round(dv[0])==round(dv[22]) || round(dv[0])==round(dv[23]) || round(dv[0])==round(dv[24]) || round(dv[0])==round(dv[25])),

      double(round(dv[1])==round(dv[2]) || round(dv[1])==round(dv[3]) || round(dv[1])==round(dv[4]) || round(dv[1])==round(dv[5]) || round(dv[1])==round(dv[6]) || round(dv[1])==round(dv[7]) || round(dv[1])==round(dv[8]) || round(dv[1])==round(dv[9]) || round(dv[1])==round(dv[10]) || round(dv[1])==round(dv[11]) || round(dv[1])==round(dv[12]) || round(dv[1])==round(dv[13]) || round(dv[1])==round(dv[14]) || round(dv[1])==round(dv[15]) || round(dv[1])==round(dv[16]) || round(dv[1])==round(dv[17]) || round(dv[1])==round(dv[18]) || round(dv[1])==round(dv[19]) || round(dv[1])==round(dv[20]) || round(dv[1])==round(dv[21]) || round(dv[1])==round(dv[22]) || round(dv[1])==round(dv[23]) || round(dv[1])==round(dv[24]) || round(dv[1])==round(dv[25])),

      double(round(dv[2])==round(dv[3]) || round(dv[2])==round(dv[4]) || round(dv[2])==round(dv[5]) || round(dv[2])==round(dv[6]) || round(dv[2])==round(dv[7]) || round(dv[2])==round(dv[8]) || round(dv[2])==round(dv[9]) || round(dv[2])==round(dv[10]) || round(dv[2])==round(dv[11]) || round(dv[2])==round(dv[12]) || round(dv[2])==round(dv[13]) || round(dv[2])==round(dv[14]) || round(dv[2])==round(dv[15]) || round(dv[2])==round(dv[16]) || round(dv[2])==round(dv[17]) || round(dv[2])==round(dv[18]) || round(dv[2])==round(dv[19]) || round(dv[2])==round(dv[20]) || round(dv[2])==round(dv[21]) || round(dv[2])==round(dv[22]) || round(dv[2])==round(dv[23]) || round(dv[2])==round(dv[24]) || round(dv[2])==round(dv[25])),

      double(round(dv[3])==round(dv[4]) || round(dv[3])==round(dv[5]) || round(dv[3])==round(dv[6]) || round(dv[3])==round(dv[7]) || round(dv[3])==round(dv[8]) || round(dv[3])==round(dv[9]) || round(dv[3])==round(dv[10]) || round(dv[3])==round(dv[11]) || round(dv[3])==round(dv[12]) || round(dv[3])==round(dv[13]) || round(dv[3])==round(dv[14]) || round(dv[3])==round(dv[15]) || round(dv[3])==round(dv[16]) || round(dv[3])==round(dv[17]) || round(dv[3])==round(dv[18]) || round(dv[3])==round(dv[19]) || round(dv[3])==round(dv[20]) || round(dv[3])==round(dv[21]) || round(dv[3])==round(dv[22]) || round(dv[3])==round(dv[23]) || round(dv[3])==round(dv[24]) || round(dv[3])==round(dv[25])),

      double(round(dv[4])==round(dv[5]) || round(dv[4])==round(dv[6]) || round(dv[4])==round(dv[7]) || round(dv[4])==round(dv[8]) || round(dv[4])==round(dv[9]) || round(dv[4])==round(dv[10]) || round(dv[4])==round(dv[11]) || round(dv[4])==round(dv[12]) || round(dv[4])==round(dv[13]) || round(dv[4])==round(dv[14]) || round(dv[4])==round(dv[15]) || round(dv[4])==round(dv[16]) || round(dv[4])==round(dv[17]) || round(dv[4])==round(dv[18]) || round(dv[4])==round(dv[19]) || round(dv[4])==round(dv[20]) || round(dv[4])==round(dv[21]) || round(dv[4])==round(dv[22]) || round(dv[4])==round(dv[23]) || round(dv[4])==round(dv[24]) || round(dv[4])==round(dv[25])),

      double(round(dv[5])==round(dv[6]) || round(dv[5])==round(dv[7]) || round(dv[5])==round(dv[8]) || round(dv[5])==round(dv[9]) || round(dv[5])==round(dv[10]) || round(dv[5])==round(dv[11]) || round(dv[5])==round(dv[12]) || round(dv[5])==round(dv[13]) || round(dv[5])==round(dv[14]) || round(dv[5])==round(dv[15]) || round(dv[5])==round(dv[16]) || round(dv[5])==round(dv[17]) || round(dv[5])==round(dv[18]) || round(dv[5])==round(dv[19]) || round(dv[5])==round(dv[20]) || round(dv[5])==round(dv[21]) || round(dv[5])==round(dv[22]) || round(dv[5])==round(dv[23]) || round(dv[5])==round(dv[24]) || round(dv[5])==round(dv[25])),

      double(round(dv[6])==round(dv[7]) || round(dv[6])==round(dv[8]) || round(dv[6])==round(dv[9]) || round(dv[6])==round(dv[10]) || round(dv[6])==round(dv[11]) || round(dv[6])==round(dv[12]) || round(dv[6])==round(dv[13]) || round(dv[6])==round(dv[14]) || round(dv[6])==round(dv[15]) || round(dv[6])==round(dv[16]) || round(dv[6])==round(dv[17]) || round(dv[6])==round(dv[18]) || round(dv[6])==round(dv[19]) || round(dv[6])==round(dv[20]) || round(dv[6])==round(dv[21]) || round(dv[6])==round(dv[22]) || round(dv[6])==round(dv[23]) || round(dv[6])==round(dv[24]) || round(dv[6])==round(dv[25])),

      double(round(dv[7])==round(dv[8]) || round(dv[7])==round(dv[9]) || round(dv[7])==round(dv[10]) || round(dv[7])==round(dv[11]) || round(dv[7])==round(dv[12]) || round(dv[7])==round(dv[13]) || round(dv[7])==round(dv[14]) || round(dv[7])==round(dv[15]) || round(dv[7])==round(dv[16]) || round(dv[7])==round(dv[17]) || round(dv[7])==round(dv[18]) || round(dv[7])==round(dv[19]) || round(dv[7])==round(dv[20]) || round(dv[7])==round(dv[21]) || round(dv[7])==round(dv[22]) || round(dv[7])==round(dv[23]) || round(dv[7])==round(dv[24]) || round(dv[7])==round(dv[25])),

      double(round(dv[8])==round(dv[9]) || round(dv[8])==round(dv[10]) || round(dv[8])==round(dv[11]) || round(dv[8])==round(dv[12]) || round(dv[8])==round(dv[13]) || round(dv[8])==round(dv[14]) || round(dv[8])==round(dv[15]) || round(dv[8])==round(dv[16]) || round(dv[8])==round(dv[17]) || round(dv[8])==round(dv[18]) || round(dv[8])==round(dv[19]) || round(dv[8])==round(dv[20]) || round(dv[8])==round(dv[21]) || round(dv[8])==round(dv[22]) || round(dv[8])==round(dv[23]) || round(dv[8])==round(dv[24]) || round(dv[8])==round(dv[25])),

      double(round(dv[9])==round(dv[10]) || round(dv[9])==round(dv[11]) || round(dv[9])==round(dv[12]) || round(dv[9])==round(dv[13]) || round(dv[9])==round(dv[14]) || round(dv[9])==round(dv[15]) || round(dv[9])==round(dv[16]) || round(dv[9])==round(dv[17]) || round(dv[9])==round(dv[18]) || round(dv[9])==round(dv[19]) || round(dv[9])==round(dv[20]) || round(dv[9])==round(dv[21]) || round(dv[9])==round(dv[22]) || round(dv[9])==round(dv[23]) || round(dv[9])==round(dv[24]) || round(dv[9])==round(dv[25])),

      double(round(dv[10])==round(dv[11]) || round(dv[10])==round(dv[12]) || round(dv[10])==round(dv[13]) || round(dv[10])==round(dv[14]) || round(dv[10])==round(dv[15]) || round(dv[10])==round(dv[16]) || round(dv[10])==round(dv[17]) || round(dv[10])==round(dv[18]) || round(dv[10])==round(dv[19]) || round(dv[10])==round(dv[20]) || round(dv[10])==round(dv[21]) || round(dv[10])==round(dv[22]) || round(dv[10])==round(dv[23]) || round(dv[10])==round(dv[24]) || round(dv[10])==round(dv[25])),

      double(round(dv[11])==round(dv[12]) || round(dv[11])==round(dv[13]) || round(dv[11])==round(dv[14]) || round(dv[11])==round(dv[15]) || round(dv[11])==round(dv[16]) || round(dv[11])==round(dv[17]) || round(dv[11])==round(dv[18]) || round(dv[11])==round(dv[19]) || round(dv[11])==round(dv[20]) || round(dv[11])==round(dv[21]) || round(dv[11])==round(dv[22]) || round(dv[11])==round(dv[23]) || round(dv[11])==round(dv[24]) || round(dv[11])==round(dv[25])),

      double(round(dv[12])==round(dv[13]) || round(dv[12])==round(dv[14]) || round(dv[12])==round(dv[15]) || round(dv[12])==round(dv[16]) || round(dv[12])==round(dv[17]) || round(dv[12])==round(dv[18]) || round(dv[12])==round(dv[19]) || round(dv[12])==round(dv[20]) || round(dv[12])==round(dv[21]) || round(dv[12])==round(dv[22]) || round(dv[12])==round(dv[23]) || round(dv[12])==round(dv[24]) || round(dv[12])==round(dv[25])),

      double(round(dv[13])==round(dv[14]) || round(dv[13])==round(dv[15]) || round(dv[13])==round(dv[16]) || round(dv[13])==round(dv[17]) || round(dv[13])==round(dv[18]) || round(dv[13])==round(dv[19]) || round(dv[13])==round(dv[20]) || round(dv[13])==round(dv[21]) || round(dv[13])==round(dv[22]) || round(dv[13])==round(dv[23]) || round(dv[13])==round(dv[24]) || round(dv[13])==round(dv[25])),

      double(round(dv[14])==round(dv[15]) || round(dv[14])==round(dv[16]) || round(dv[14])==round(dv[17]) || round(dv[14])==round(dv[18]) || round(dv[14])==round(dv[19]) || round(dv[14])==round(dv[20]) || round(dv[14])==round(dv[21]) || round(dv[14])==round(dv[22]) || round(dv[14])==round(dv[23]) || round(dv[14])==round(dv[24]) || round(dv[14])==round(dv[25])),

      double(round(dv[15])==round(dv[16]) || round(dv[15])==round(dv[17]) || round(dv[15])==round(dv[18]) || round(dv[15])==round(dv[19]) || round(dv[15])==round(dv[20]) || round(dv[15])==round(dv[21]) || round(dv[15])==round(dv[22]) || round(dv[15])==round(dv[23]) || round(dv[15])==round(dv[24]) || round(dv[15])==round(dv[25])),

      double(round(dv[16])==round(dv[17]) || round(dv[16])==round(dv[18]) || round(dv[16])==round(dv[19]) || round(dv[16])==round(dv[20]) || round(dv[16])==round(dv[21]) || round(dv[16])==round(dv[22]) || round(dv[16])==round(dv[23]) || round(dv[16])==round(dv[24]) || round(dv[16])==round(dv[25])),

      double(round(dv[17])==round(dv[18]) || round(dv[17])==round(dv[19]) || round(dv[17])==round(dv[20]) || round(dv[17])==round(dv[21]) || round(dv[17])==round(dv[22]) || round(dv[17])==round(dv[23]) || round(dv[17])==round(dv[24]) || round(dv[17])==round(dv[25])),

      double(round(dv[18])==round(dv[19]) || round(dv[18])==round(dv[20]) || round(dv[18])==round(dv[21]) || round(dv[18])==round(dv[22]) || round(dv[18])==round(dv[23]) || round(dv[18])==round(dv[24]) || round(dv[18])==round(dv[25])),

      double(round(dv[19])==round(dv[20]) || round(dv[19])==round(dv[21]) || round(dv[19])==round(dv[22]) || round(dv[19])==round(dv[23]) || round(dv[19])==round(dv[24]) || round(dv[19])==round(dv[25])),

      double(round(dv[20])==round(dv[21]) || round(dv[20])==round(dv[22]) || round(dv[20])==round(dv[23]) || round(dv[20])==round(dv[24]) || round(dv[20])==round(dv[25])),

      double(round(dv[21])==round(dv[22]) || round(dv[21])==round(dv[23]) || round(dv[21])==round(dv[24]) || round(dv[21])==round(dv[25])),

      double(round(dv[22])==round(dv[23]) || round(dv[22])==round(dv[24]) || round(dv[22])==round(dv[25])),

      double(round(dv[23])==round(dv[24]) || round(dv[23])==round(dv[25])),

      double(round(dv[24])==round(dv[25]))
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
    return key_length;
  }
  pagmo::vector_double::size_type get_ncx() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      evaluate(vigenere_decrypt(ciphertext,dv,key_length)),
      //known_plaintext("YEAR",vigenere_decrypt(ciphertext,dv,key_length))
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
  pagmo::vector_double::size_type get_ncx() const{
    return 0;
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
      pagmo::vector_double(25,0),pagmo::vector_double(25,24),
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
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      rsa_fitness(dv,n), //objective function
      /*
      ensure_sum_inequality(dv,n), //(x+y!=n)
      ensure_non_trivial(dv,n),
      double(prime_vector_to_int(dv,0)-n),
      double(prime_vector_to_int(dv,PRIME_BASE_SIZE)-n),
      //ensure_inequality(dv,n), //inequality constraint (x<y)
      */
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(2*PRIME_BASE_SIZE,0),pagmo::vector_double(2*PRIME_BASE_SIZE,5),
    };
  }
};

struct rsa_factor_alternative {
  int4096_t n;
  int4096_t lb;
  int4096_t ub;
  pagmo::vector_double::size_type get_nix() const{
    return PRIME_BASE_SIZE;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      rsa_fitness_alternative(dv,n,lb,ub), //objective function
      /*
      ensure_sum_inequality(dv,n), //(x+y!=n)
      ensure_non_trivial(dv,n),
      double(prime_vector_to_int(dv,0)-n),
      double(prime_vector_to_int(dv,PRIME_BASE_SIZE)-n),
      //ensure_inequality(dv,n), //inequality constraint (x<y)
      */
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(PRIME_BASE_SIZE,0),pagmo::vector_double(PRIME_BASE_SIZE,5),
    };
  }
};

struct rsa_rutkowski_houghten {
  int4096_t n;
  int bits;
  pagmo::vector_double::size_type get_nix() const{
    return bits;
  }
  pagmo::vector_double::size_type get_nec() const{
    return 0;
  }
  pagmo::vector_double::size_type get_nic() const{
    return 0;
  }
  pagmo::vector_double fitness(const pagmo::vector_double &dv) const{
    return {
      rsa_fitness_houghten_rutkowski(dv,n), //objective function
      /*
      ensure_sum_inequality(dv,n), //(x+y!=n)
      ensure_non_trivial(dv,n),
      double(prime_vector_to_int(dv,0)-n),
      double(prime_vector_to_int(dv,PRIME_BASE_SIZE)-n),
      //ensure_inequality(dv,n), //inequality constraint (x<y)
      */
    };
  }
  std::pair<pagmo::vector_double,pagmo::vector_double> get_bounds() const{
    return {
      pagmo::vector_double(bits,0),pagmo::vector_double(bits,1),
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
    return 12;
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
      pagmo::vector_double(12,0),pagmo::vector_double(12,255),
    };
  }
};
