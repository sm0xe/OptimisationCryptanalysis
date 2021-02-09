#include "config.h"
#include <string>
#include <iostream>
#include <fstream>
#include <getopt.h>
#include <math.h>
#include <map>
#include <cryptopp/des.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>

#define DEBUG
using namespace std;

map<char,int> get_monogram_frequencies(string ciphertext); // from analysis.cpp
map<string,int> get_digram_frequencies(string ciphertext); // from analysis.cpp
bool test_substitutions(); //from substitution.cpp
bool test_vigenere(); //from vigenere.cpp
bool test_playfair(); //from playfair.cpp
void test_des(array<std::byte,CryptoPP::DES::DEFAULT_KEYLENGTH> keyarray); //from des.cpp
void test_aes(array<std::byte,CryptoPP::AES::DEFAULT_KEYLENGTH> keyarray); //from aes.cpp
void test_rsa(); //from rsa.cpp
string des_encrypt(array<std::byte,CryptoPP::DES::DEFAULT_KEYLENGTH> keyarray,string plaintext); //from des.cpp
string des_decrypt(array<std::byte,CryptoPP::DES::DEFAULT_KEYLENGTH> keyarray,string ciphertext); //from des.cpp
string aes_encrypt(array<std::byte,CryptoPP::AES::DEFAULT_KEYLENGTH> keyarray,string plaintext); //from aes.cpp
string aes_decrypt(array<std::byte,CryptoPP::AES::DEFAULT_KEYLENGTH> keyarray,string ciphertext); //from aes.cpp

const char* prog_name;

enum cipher_choice {nocipher,msub,vigenere,playfair,sdes,four_des,des,simple_aes,aes,rsa_fact,rsa,simon} cipher=nocipher;
enum optimization_choice {none,de,sa,pso,ant,bee,cuckoo} optimize=none;

void print_usage(int exit_code){
  cout << "Usage: " << prog_name << " options [ args ... ]\n";
  cout << " -h      --help                      Display this usage information.\n";
  cout << " -c      --cipher [cipher]           Select cipher\n";
  cout << " -o      --optimize [optimization]   Select optimization algorithm\n";
  cout << " -l      --list                      List supported ciphers and optimization algorithms.\n";
  cout << "\nExamples:\n";
  cout << " " << prog_name << " -c msub -o de substituted.txt    Use differential evolution to crack a substitution cipher\n";
  exit(exit_code);
}

void list_options(){
  cout << "Supported ciphers:" << endl;
  cout << "  Monoalphabetic Substitution Cipher (msub)" << endl;
  cout << "  Vigenere Cipher (vigenere)" << endl;
  cout << "  Playfair Cipher (playfair)" << endl;
  //cout << "  Simple DES (sdes)" << endl;
  //cout << "  4-round DES (four_des)" << endl;
  cout << "  Full DES (des)" << endl;
  //cout << "  Simple AES (simple_aes)" << endl;
  cout << "  Full AES (aes)" << endl;
  //cout << "  RSA Factorization Problem (rsa_fact)" << endl;
  //cout << "  Ciphertext-only RSA (rsa)" << endl;
  //cout << "  SIMON (simon)" << endl;
  cout << "Supported optimization algorithms/schemes:" << endl;
  cout << "  Self-adaptive Differential Evolution/Genetic Algorithm (de)" << endl;
  //cout << "  Simulated Annealing (sa)" << endl;
  //cout << "  Particle Swarm Optimization (particle)" << endl;
  //cout << "  Ant Colony Optimization (ant)" << endl;
  //cout << "  Artificial Bee Colony Algorithm (bee)" << endl;
  //cout << "  Cuckoo Search (cuckoo)" << endl;
  exit(0);
}

void select_cipher(string opt){
  if(opt == "msub"){
      cipher = msub;
  }
  else if(opt == "vigenere"){
      cipher = vigenere;
  }
  else if(opt == "sdes"){
      cipher = sdes;
  }
  else if(opt == "four_des"){
      cipher = four_des;
  }
  else if(opt == "des"){
      cipher = des;
  }
  else if(opt == "simple_aes"){
      cipher = simple_aes;
  }
  else if(opt == "aes"){
      cipher = aes;
  }
  else if(opt == "simon"){
      cipher = simon;
  }
  else{
      cout << "I'm sorry, '" << opt << "' is not a supported cipher" << endl;
      exit(1);
  }
}

void select_optimization(string opt){
  if(opt == "de"){
      optimize = de;
  }
  else if(opt == "sa"){
      optimize = sa;
  }
  else if(opt == "particle"){
      optimize = pso;
  }
  else if(opt == "ant"){
      optimize = ant;
  }
  else if(opt == "bee"){
      optimize = bee;
  }
  else if(opt == "cuckoo"){
      optimize = cuckoo;
  }
  else{
      cout << "I'm sorry, '" << opt << "' is not a supported optimization algorithm" << endl;
      exit(1);
  }
}

int main(int argc, char* argv[]){
  prog_name = argv[0];
  
  int next_opt;
  string filename;
  string ciphertext;

  const char* short_opt = "hc:o:l";

  const struct option long_opt[] = {
    { "help", 0, NULL, 'h' },
    { "cipher", 1, NULL, 'c' },
    { "optimize", 1, NULL, 'o' },
    { "list", 0, NULL, 'l' },
  };

  while((next_opt=getopt_long(argc,argv,short_opt,long_opt,NULL))!=-1){
    string opt;
    switch(next_opt){
      case 0: //Option sets a flag, do nothing
        cout << "0" << endl;
        break;
      case 'h':
        print_usage(0);
        break;
      case 'c':
        select_cipher(optarg);
        break;
      case 'o':
        select_optimization(optarg);
        break;
      case 'l':
        list_options();
        break;
      case '?':
        print_usage(1);
        break;
      case -1:
        break;
      default:
        abort();
    }
  }
  if(optind==argc){
    print_usage(1);
  }
  filename = argv[optind]; //Get filename

  fstream file;
  file.open(filename, ios::in);
  if(file.is_open()){
    string line;
    while( getline(file,line)){
      ciphertext.append(line+"\n");
    }
    file.close();
  }
  else{
    cout << "Cannot open '" << filename << "': No such file" << endl;
  }

  string decrypted;

  if(cipher == msub){
    cout << "You chose the Monoalphabetic Substitution Cipher with ";
#ifdef DEBUG
  map<char,int> mfreqs = get_monogram_frequencies(ciphertext);
  map<string,int> dfreqs = get_digram_frequencies(ciphertext);
  for(auto &pair : mfreqs){
    cout << pair.first << " : " << pair.second << endl;
  }
  for(auto &pair : dfreqs){
    cout << pair.first << " : " << pair.second << endl;
  }
#endif
  }
  else if(cipher == vigenere){
    cout << "You chose the Vigenere Cipher with ";
#ifdef DEBUG
  map<char,int> mfreqs = get_monogram_frequencies(ciphertext);
  map<string,int> dfreqs = get_digram_frequencies(ciphertext);
  for(auto &pair : mfreqs){
    cout << pair.first << " : " << pair.second << endl;
  }
  for(auto &pair : dfreqs){
    cout << pair.first << " : " << pair.second << endl;
  }
#endif
  }
  else if(cipher == playfair){
    cout << "You chose the Playfair Cipher with ";
  }
  else if(cipher == des){
    cout << "You chose DES with ";
    array<byte,CryptoPP::DES::DEFAULT_KEYLENGTH> hex_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37};
    decrypted = des_decrypt(hex_key,ciphertext);
  }
  else if(cipher == aes){
    cout << "You chose AES with ";
    array<byte,CryptoPP::AES::DEFAULT_KEYLENGTH> hex_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe, (byte) 0x10, (byte) 0x37, (byte) 0xde, (byte) 0xf0 };
    decrypted = aes_decrypt(hex_key,ciphertext);
  }

  if(optimize == de){
    cout << "Self-adaptive Differential Evolution";
  }

  cout << " for " << filename << endl;

  cout << decrypted << endl;


#ifdef DEBUG
  array<byte,CryptoPP::DES::DEFAULT_KEYLENGTH> des_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x00, (byte) 0x00};
  array<byte,CryptoPP::AES::DEFAULT_KEYLENGTH> aes_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe, (byte) 0x10, (byte) 0x37, (byte) 0xde, (byte) 0xf0 };
  cout << "Substitutions: " << test_substitutions() << endl;
  cout << "Vigenere:      " << test_vigenere() << endl;
  cout << "Playfair:      " << test_playfair() << endl;
  cout << "DES:           " << endl;
  test_des(des_key);
  cout << "AES:           " << endl;
  test_aes(aes_key);
  cout << "RSA:           " << endl;
  test_rsa();
#endif

  //print_usage(0); //Why are we here. We should never get this far.
}
