#include "config.h"
#include "helpers/optimization_problems.h"
#include "helpers/crypto_functions.h"

#include <string>
#include <iostream>
#include <fstream>
#include <getopt.h>
#include <math.h>
#include <map>

#include <cryptopp/des.h>
#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/speck.h>

#include <pagmo/algorithm.hpp>
#include <pagmo/algorithms/sade.hpp>
#include <pagmo/algorithms/simulated_annealing.hpp>
#include <pagmo/algorithms/pso.hpp>
#include <pagmo/algorithms/gaco.hpp>
#include <pagmo/algorithms/bee_colony.hpp>
#include <pagmo/population.hpp>
#include <pagmo/problem.hpp>
#include <pagmo/types.hpp>

//#define DEBUG
#define GENERATIONS 100000000
#define POP_SIZE 10000
using namespace std;

const char* prog_name;

enum cipher_choice {nocipher,msub,vigenere,playfair,sdes,four_des,des,simple_aes,aes,rsa_fact,rsa,speck} cipher=nocipher;
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
  cout << "  SPECK (speck)" << endl;
  cout << "Supported optimization algorithms/schemes:" << endl;
  cout << "  Self-adaptive Differential Evolution/Genetic Algorithm (de)" << endl;
  cout << "  Simulated Annealing (sa)" << endl;
  cout << "  Particle Swarm Optimization (particle)" << endl;
  cout << "  Ant Colony Optimization (ant)" << endl;
  cout << "  Artificial Bee Colony Algorithm (bee)" << endl;
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
  else if(opt == "speck"){
      cipher = speck;
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
  pagmo::problem opt_problem;
  pagmo::algorithm opt_algo;

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
    opt_problem = pagmo::problem{msub_generic{.ciphertext=ciphertext}};
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
    opt_problem = pagmo::problem{vigenere_generic{.ciphertext=ciphertext,.key_length=5}};
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
    opt_problem = pagmo::problem{playfair_generic{.ciphertext=ciphertext}};
  }
  else if(cipher == des){
    cout << "You chose DES with ";
    opt_problem = pagmo::problem{des_generic{.ciphertext=ciphertext}};
  }
  else if(cipher == aes){
    cout << "You chose AES with ";
    opt_problem = pagmo::problem{aes_generic{.ciphertext=ciphertext}};
  }
  else if(cipher == speck){
    cout << "You chose SPECK with ";
    opt_problem = pagmo::problem{speck_generic{.ciphertext=ciphertext}};
  }

  if(optimize == de){
    cout << "Self-adaptive Differential Evolution";
    pagmo::algorithm opt_algo{pagmo::sade(GENERATIONS)};
  }
  if(optimize == sa){
    cout << "Simulated Annealing";
    pagmo::algorithm opt_algo{pagmo::simulated_annealing(GENERATIONS)};
  }
  if(optimize == pso){
    cout << "Particle Swarm Optimization";
    pagmo::algorithm opt_algo{pagmo::pso(GENERATIONS)};
  }
  if(optimize == ant){
    cout << "Ant Colony Optimization";
    pagmo::algorithm opt_algo{pagmo::gaco(GENERATIONS)};
  }
  if(optimize == bee){
    cout << "Artifical Bee Colony";
    pagmo::algorithm opt_algo{pagmo::bee_colony(GENERATIONS)};
  }
  if(optimize == cuckoo){
    cout << "Cuckoo Search";
    pagmo::algorithm opt_algo{cuckoo_search(GENERATIONS)};
  }

  cout << " for " << filename << endl;

  cout << decrypted << endl;

  pagmo::population pop(opt_problem,POP_SIZE);

  pop = opt_algo.evolve(pop);

  cout << "The population: \n" << pop << std::endl;
  pagmo::vector_double best = pop.champion_x();
  string keystring = "";
  cout << "Best fitness vector, with fitness " << pop.champion_f()[0] << ":" << endl;
  for(auto i : best){
    cout << i << ", ";
    keystring+=int_to_hex((int)i);
  }
  cout << endl;
  cout << "Key: " << keystring << endl;

  if(cipher == msub){
    //std::string key = "";
    //for(auto i : best){
    //  key+=(char)i+'A';
    //}
    //cout << "key: " << key << endl;
    cout << substitute(ciphertext,best) << endl;
  }
  if(cipher == vigenere){
    cout << vigenere_decrypt(ciphertext,best,5) << endl;
  }
  if(cipher == aes){
    cout << aes_decrypt(best,ciphertext) << endl;
  }
  

#ifdef DEBUG
  array<byte,CryptoPP::DES::DEFAULT_KEYLENGTH> des_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37};
  array<byte,CryptoPP::AES::DEFAULT_KEYLENGTH> aes_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe, (byte) 0x10, (byte) 0x37, (byte) 0xde, (byte) 0xf0 };
  array<byte,CryptoPP::SPECK64::DEFAULT_KEYLENGTH> speck_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe };
  cout << "Substitutions: " << test_substitutions() << endl;
  cout << "Vigenere:      " << test_vigenere() << endl;
  cout << "Playfair:      " << test_playfair() << endl;
  cout << "DES:           " << endl;
  test_des(des_key);
  cout << "AES:           " << endl;
  test_aes(aes_key);
  cout << "RSA:           " << endl;
  test_rsa();
  cout << "SPECK:           " << endl;
  test_speck(speck_key);
#endif

  //print_usage(0); //Why are we here. We should never get this far.
}
