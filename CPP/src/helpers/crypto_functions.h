#include <cryptopp/des.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/speck.h>
#include "boost/multiprecision/cpp_int.hpp"

typedef boost::multiprecision::number<boost::multiprecision::cpp_int_backend<4096, 4096, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked, void> >  int4096_t;

int4096_t gcd(int4096_t a, int4096_t b);

std::map<char,int> get_monogram_frequencies(std::string ciphertext); // from analysis.cpp
std::map<std::string,int> get_digram_frequencies(std::string ciphertext); // from analysis.cpp
std::map<std::string,int> get_trigram_frequencies(std::string ciphertext); // from analysis.cpp
double index_of_coincidence(int,std::map<char,int>); //from analysis.cpp
int find_vigenere_key_length(std::string); //from analysis.cpp

unsigned int count_equal_bits(pagmo::vector_double,std::vector<std::byte>); // from keychecker.cpp

std::string int_to_hex(int n); // from hexifier.cpp

std::string columnar_encode(std::string,int[],int); //from columnar.cpp
std::string columnar_decode(std::string,int[],int); //from columnar.cpp
std::string columnar_decode(std::string,pagmo::vector_double); //from columnar.cpp
pagmo::vector_double columnar_key_from_dv(pagmo::vector_double); //from columnar.cpp

std::string rail_fence_encode(std::string,int); //from rail_fence.cpp
std::string rail_fence_decode(std::string,int); //from rail_fence.cpp

bool test_substitutions(); //from substitution.cpp
std::string substitute(std::string orig, std::string key);
std::string substitute(std::string orig, const pagmo::vector_double &dv);
std::string dv_to_msub_key(const pagmo::vector_double &dv); // from substitution.cpp

bool test_vigenere(); //from vigenere.cpp
std::string vigenere_decrypt(std::string ciphertext, const pagmo::vector_double &dv, int length);
//std::string vigenere_decrypt(std::string ciphertext, std::string);

bool test_playfair(); //from playfair.cpp
std::string playfair_encrypt(std::string plaintext, std::string key);
std::string playfair_decrypt(std::string ciphertext, std::string key);
std::string playfair_decrypt(std::string ciphertext, const pagmo::vector_double &dv);
std::string dv_to_pf_key(const pagmo::vector_double &dv); // from playfair.cpp

void test_des(std::array<std::byte,CryptoPP::DES::DEFAULT_KEYLENGTH> keyarray); //from des.cpp
std::string des_encrypt(std::array<std::byte,CryptoPP::DES::DEFAULT_KEYLENGTH> keyarray,std::string plaintext); //from des.cpp
std::string des_decrypt(std::array<std::byte,CryptoPP::DES::DEFAULT_KEYLENGTH> keyarray,std::string ciphertext); //from des.cpp
std::string des_decrypt(const pagmo::vector_double &dv, std::string ciphertext); //from des.cpp

void test_aes(std::array<std::byte,CryptoPP::AES::DEFAULT_KEYLENGTH> keyarray); //from aes.cpp
std::string aes_encrypt(std::array<std::byte,CryptoPP::AES::DEFAULT_KEYLENGTH> keyarray,std::string plaintext); //from aes.cpp
std::string aes_decrypt(std::array<std::byte,CryptoPP::AES::DEFAULT_KEYLENGTH> keyarray,std::string ciphertext); //from aes.cpp
std::string aes_decrypt(const pagmo::vector_double &dv,std::string ciphertext); //from aes.cpp

void test_rsa(); //from rsa.cpp
std::string rsa_encrypt(CryptoPP::RSA::PublicKey publicKey,std::string plaintext); //from rsa.cpp
std::string rsa_decrypt(CryptoPP::RSA::PrivateKey privateKey,std::string ciphertexttext); //from rsa.cpp

void test_speck(std::array<std::byte,CryptoPP::SPECK64::DEFAULT_KEYLENGTH> keyarray); //from speck.cpp
std::string speck_encrypt(std::array<std::byte,CryptoPP::SPECK64::DEFAULT_KEYLENGTH> keyarray,std::string plaintext); //from speck.cpp
std::string speck_decrypt(std::array<std::byte,CryptoPP::SPECK64::DEFAULT_KEYLENGTH> keyarray,std::string ciphertext); //from speck.cpp
std::string speck_decrypt(const pagmo::vector_double &dv,std::string ciphertext); //from speck.cpp
