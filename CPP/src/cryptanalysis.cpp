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
#include <pagmo/algorithms/sga.hpp>
#include <pagmo/algorithms/de1220.hpp>
#include <pagmo/algorithms/sade.hpp>
#include <pagmo/algorithms/simulated_annealing.hpp>
#include <pagmo/algorithms/pso.hpp>
#include <pagmo/algorithms/gaco.hpp>
#include <pagmo/algorithms/bee_colony.hpp>
#include "helpers/cuckoo_search.hpp"
#include <pagmo/population.hpp>
#include <pagmo/problem.hpp>
#include <pagmo/types.hpp>

#define DEBUG
#define GENERATIONS 100
using namespace std;

void extract_log(pagmo::algorithm,string);

const char* prog_name;

enum cipher_choice {nocipher,caesar,columnar,rail_fence,msub,vigenere,playfair,sdes,four_des,des,simple_aes,aes,rsa_fact,rsa,speck} cipher=nocipher;
enum optimization_choice {none,ga,de,sa,pso,ant,bee,cuckoo} optimize=none;

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
  cout << "  Caesar/Shift Cipher (caesar)" << endl;
  cout << "  Rail Fence Cipher (rail_fence)" << endl;
  cout << "  Monoalphabetic Substitution Cipher (msub)" << endl;
  cout << "  Vigenere Cipher (vigenere)" << endl;
  cout << "  Playfair Cipher (playfair)" << endl;
  //cout << "  Simple DES (sdes)" << endl;
  //cout << "  4-round DES (four_des)" << endl;
  cout << "  Full DES (des)" << endl;
  //cout << "  Simple AES (simple_aes)" << endl;
  cout << "  Full AES (aes)" << endl;
  cout << "  RSA Factorization Problem (rsa_fact)" << endl;
  //cout << "  Ciphertext-only RSA (rsa)" << endl;
  cout << "  SPECK (speck)" << endl;
  cout << "Supported optimization algorithms/schemes:" << endl;
  cout << "  Simple Genetic Algorithm (ga)" << endl;
  cout << "  Differential Evolution (de)" << endl;
  cout << "  Simulated Annealing (sa)" << endl;
  cout << "  Particle Swarm Optimization (particle)" << endl;
  cout << "  Ant Colony Optimization (ant)" << endl;
  cout << "  Artificial Bee Colony Algorithm (bee)" << endl;
  cout << "  Cuckoo Search (cuckoo)" << endl;
  exit(0);
}

void select_cipher(string opt){
  if(opt == "caesar"){
    cipher = caesar;
  }
  else if(opt == "columnar"){
    cipher = columnar;
  }
  else if(opt == "rail_fence"){
    cipher = rail_fence;
  }
  else if(opt == "msub"){
    cipher = msub;
  }
  else if(opt == "vigenere"){
    cipher = vigenere;
  }
  else if(opt == "playfair"){
    cipher = playfair;
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
  else if(opt == "rsa_fact"){
    cipher = rsa_fact;
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
  if(opt == "ga"){
    optimize = ga;
  }
  else if(opt == "de"){
    optimize = de;
  }
  else if(opt == "sa"){
    optimize = sa;
  }
  else if(opt == "particle" || opt == "pso"){
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
  int population = 20;
  string filename;
  string ciphertext;
  string log_file = "";
  pagmo::problem opt_problem;
  pagmo::algorithm opt;

  const char* short_opt = "hc:o:lf:p:";

  const struct option long_opt[] = {
    { "help", 0, NULL, 'h' },
    { "cipher", 1, NULL, 'c' },
    { "optimize", 1, NULL, 'o' },
    { "list", 0, NULL, 'l' },
    { "pop", 1, NULL, 'p' },
    { "log_file",1, NULL, 'f' }
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
      case 'p':
        population = stoi(optarg);
        break;
      case '?':
        print_usage(1);
        break;
      case 'f':
        log_file = optarg;
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
    ciphertext.erase(ciphertext.length()-1);
    file.close();
  }
  else{
    cout << "Cannot open '" << filename << "': No such file" << endl;
  }

  string decrypted;
  int key_length=0;

  cout.setf(ios::fixed, ios::floatfield);
  cout.setf(ios::showpoint);
  cout.precision(2);
  /*
  cout << evaluate(ciphertext) << endl;
  exit(0);
  */

  if(cipher == caesar){
    cout << "You chose the Caesar/Shift Cipher with ";
    opt_problem = pagmo::problem{shift_generic{.ciphertext=ciphertext}};
  }
  else if(cipher == columnar){
    cout << "You chose the Columnar Transposition Cipher with ";
    opt_problem = pagmo::problem{columnar_generic{.ciphertext=ciphertext,.max_cols=4}};
  }
  else if(cipher == rail_fence){
    cout << "You chose the Rail Fence Cipher with ";
    opt_problem = pagmo::problem{rail_fence_generic{.ciphertext=ciphertext,.max_rails=ciphertext.size()/2}};
  }
  else if(cipher == msub){
    cout << "You chose the Monoalphabetic Substitution Cipher with ";
    opt_problem = pagmo::problem{msub_generic{.ciphertext=ciphertext}};
  }
  else if(cipher == vigenere){
    std::string stripped;
    for(auto i : ciphertext){
      if((i>='A' && i<='Z') || (i>='a' && i<='z')){
        stripped+=i;
      }
    }
    key_length = find_vigenere_key_length(stripped); 
    cout << "###Key length is probably " << key_length << endl;
    cout << "You chose the Vigenere Cipher with ";
    opt_problem = pagmo::problem{vigenere_generic{.ciphertext=ciphertext,.key_length=key_length}};
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
  else if(cipher == rsa_fact){
    cout << "You chose RSA Factorization with ";
    ciphertext.erase(std::remove(ciphertext.begin(),ciphertext.end(),'\n'),ciphertext.end());
    opt_problem = pagmo::problem{rsa_factor{.n=int4096_t(ciphertext)}};
  }
  else if(cipher == speck){
    cout << "You chose SPECK with ";
    opt_problem = pagmo::problem{speck_generic{.ciphertext=ciphertext}};
  }

  if(optimize == ga){
    cout << "Simple Genetic Algorithm";
    //sga(unsigned gen = 1u, double cr = .90, double eta_c = 1., double m = 0.02, double param_m = 1., unsigned param_s = 2u, std::string crossover = "exponential", std::string mutation = "polynomial", std::string selection = "tournament", unsigned seed = pagmo::random_device::next())
    auto opt_algo = pagmo::sga(GENERATIONS,.75,1,0.02,1,5u,"exponential","uniform","tournament");
#ifdef DEBUG
    opt_algo.set_verbosity(2);
#endif
    opt = pagmo::algorithm{opt_algo};
  }
  if(optimize == de){
    cout << "Differential Evolution";
    //vector<unsigned> allowed = {6u,7u,8u,9u,10u,12u,14u,16u,18u};
    pagmo::algorithm opt_algo{pagmo::de1220(GENERATIONS)};
    //pagmo::algorithm opt_algo{pagmo::de1220(GENERATIONS,allowed,1u,1e5,1e-6)};
    //pagmo::algorithm opt_algo{pagmo::sade(GENERATIONS)};
#ifdef DEBUG
    opt_algo.set_verbosity(1);
#endif
    opt = pagmo::algorithm{opt_algo};
  }
  if(optimize == sa){
    cout << "Simulated Annealing";
    auto opt_algo = pagmo::simulated_annealing();
#ifdef DEBUG
    opt_algo.set_verbosity(1);
#endif
    opt = pagmo::algorithm{opt_algo};
  }
  if(optimize == pso){
    cout << "Particle Swarm Optimization";
    auto opt_algo = pagmo::pso(GENERATIONS);
#ifdef DEBUG
    opt_algo.set_verbosity(1);
#endif
    opt = pagmo::algorithm{opt_algo};
  }
  if(optimize == ant){
    cout << "Ant Colony Optimization";
    auto opt_algo = pagmo::gaco(max(GENERATIONS,63));
#ifdef DEBUG
    opt_algo.set_verbosity(1);
#endif
    opt = pagmo::algorithm{opt_algo};
  }
  if(optimize == bee){
    cout << "Artifical Bee Colony";
    auto opt_algo = pagmo::bee_colony(GENERATIONS);
#ifdef DEBUG
    opt_algo.set_verbosity(1);
#endif
    opt = pagmo::algorithm{opt_algo};
  }
  if(optimize == cuckoo){
    cout << "Cuckoo Search";
    auto opt_algo = pagmo::cuckoo_search(GENERATIONS,0.25,1.0);
#ifdef DEBUG
    opt_algo.set_verbosity(1);
#endif
    opt = pagmo::algorithm{opt_algo};
  }

  cout << " for " << filename << endl;

  cout << "Population size: " << population << endl;
  cout << "Generations    : " << GENERATIONS <<  endl;

  pagmo::population pop(opt_problem,population);
  if(cipher == msub){
    //pop.push_back(pagmo::vector_double({'C'-'A', 'B'-'A', 'R'-'A', 'S'-'A', 'T'-'A', 'F'-'A', 'U'-'A', 'Z'-'A', 'N'-'A', 'D'-'A', 'O'-'A', 'I'-'A', 'K'-'A', 'A'-'A', 'G'-'A', 'L'-'A', 'W'-'A', 'V'-'A', 'X'-'A', 'Y'-'A', 'P'-'A', 'Q'-'A', 'H'-'A', 'M'-'A', 'E'-'A', 'J'-'A'}));
    //pop.push_back(pagmo::vector_double({'C'-'A', 'B'-'A', 'R'-'A', 'S'-'A', 'T'-'A', 'F'-'A', 'U'-'A', 'Z'-'A', 'N'-'A', 'D'-'A', 'O'-'A', 'I'-'A', 'K'-'A', 'A'-'A', 'G'-'A', 'L'-'A', 'W'-'A', 'V'-'A', 'X'-'A', 'Y'-'A', 'P'-'A', 'Q'-'A', 'H'-'A', 'M'-'A', 'J'-'A', 'E'-'A'}));
    //pop.push_back(pagmo::vector_double({'N'-'A', 'T'-'A', 'A'-'A', 'P'-'A', 'Y'-'A', 'X'-'A', 'U'-'A', 'W'-'A', 'K'-'A', 'S'-'A', 'M'-'A', 'J'-'A', 'F'-'A', 'L'-'A', 'I'-'A', 'Q'-'A', 'H'-'A', 'C'-'A', 'D'-'A', 'E'-'A', 'G'-'A', 'R'-'A', 'O'-'A', 'V'-'A', 'B'-'A', 'Z'-'A'}));
    //pop.push_back(pagmo::vector_double({0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25}));
  }
  if(cipher == vigenere){
    //pop.push_back(pagmo::vector_double({9,20,11,4,18}));
  }
  if(cipher == playfair){
    //pop.push_back(pagmo::vector_double({15,11,0,24,5,8,17,4,23,12,1,2,3,6,7,10,13,14,16,18,19,20,21,22,25}));
    //pop.push_back(pagmo::vector_double({15,11,0,24,5,8,17,4,23,12,1,2,3,6,7}));
    //pop.push_back(pagmo::vector_double({0,1,2,3,4,5,6,7,8,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25}));
  }
  if(cipher == des){
    //pop.push_back(pagmo::vector_double({0xde, 0xad, 0xbe, 0xef, 0xba, 0xbe, 0x13, 0x37}));
  }
  if(cipher == aes){
    pop.push_back(pagmo::vector_double({0xde, 0xad, 0xbe, 0xef, 0xba, 0xbe, 0x13, 0x37, 0xfe, 0xed, 0x7a, 0xbe, 0x10, 0x37, 0xde, 0xf0}));
  }
  if(cipher == speck){
    pop.push_back(pagmo::vector_double({0xde, 0xad, 0xbe, 0xef, 0xba, 0xbe, 0x13, 0x37, 0xfe, 0xed, 0x7a, 0xbe}));
  }

  pop = opt.evolve(pop);


  if(population<=10000){
    cout << "The population: \n" << pop << std::endl;
  }
  pagmo::vector_double best = pop.champion_x();
  string keystring = "";
  cout << "Best fitness vector, with fitness " << pop.champion_f()[0] << ":" << endl;
  cout << endl;
  for(auto i : best){
    cout.width(3);
    cout << i << ", ";
    if(cipher == des || cipher == aes || cipher == speck){
      keystring+=int_to_hex((int)i);
    }
    else{
      keystring+=(char)('A'+round(i));
    }
  }
  cout << endl;
  if(cipher == caesar){
    cout << endl << "msub key: " << shift_to_msub_key(int(best[0])) << endl;
  }
  if(cipher == msub){
    cout << endl << "msub key: " << dv_to_msub_key(best) << endl;
  }
  if(cipher == playfair){
    cout << endl << "playfair key: " << dv_to_pf_key(best) << endl;
  }
  /*
  if(cipher == msub || cipher == playfair){
    for(int i=0; i<best.size(); i++){
      bool found = false;
      for(int j=0; j<best.size(); j++){
        if(best[i]==best[j] && i!=j){
          found=true;
          break;
        }
      }
      cout.width(3);
      if(found){
        cout << "^";
      }
      else{
        cout << " ";
      }
      cout << "  ";
    }
  }*/
  if(cipher != rsa_fact){
    cout << "Key: " << keystring << endl << endl;
  }
  string plaintext;
  unsigned int correct;
  if(cipher == caesar){
    plaintext = substitute(ciphertext,shift_to_msub_key(best[0]));
  }
  if(cipher == columnar){
    plaintext = columnar_decode(ciphertext,best);
  }
  if(cipher == rail_fence){
    plaintext = rail_fence_decode(ciphertext,round(best[0]));
  }
  if(cipher == msub){
    plaintext = substitute(ciphertext,dv_to_msub_key(best));
  }
  if(cipher == vigenere){
    plaintext = vigenere_decrypt(ciphertext,best,key_length);
  }
  if(cipher == playfair){
    plaintext = playfair_decrypt(ciphertext,best);
  }
  if(cipher == des){
    plaintext = des_decrypt(best,ciphertext);
    array<byte,CryptoPP::DES::DEFAULT_KEYLENGTH> des_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37};
    correct = count_equal_bits(best,vector<std::byte>(des_key.begin(),des_key.end()));
    cout << "Correct: " << correct << "/64 bits" << endl;
  }
  if(cipher == aes){
    plaintext = aes_decrypt(best,ciphertext);
    array<byte,CryptoPP::AES::DEFAULT_KEYLENGTH> aes_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe, (byte) 0x10, (byte) 0x37, (byte) 0xde, (byte) 0xf0 };
    correct = count_equal_bits(best,vector<std::byte>(aes_key.begin(),aes_key.end()));
    cout << "Correct: " << correct << "/128 bits" << endl;
  }
  if(cipher == speck){
    plaintext = speck_decrypt(best,ciphertext);
    array<byte,CryptoPP::SPECK64::DEFAULT_KEYLENGTH> speck_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe };
    correct = count_equal_bits(best,vector<std::byte>(speck_key.begin(),speck_key.end()));
    cout << "Correct: " << correct << "/96 bits" << endl;
  }
  if(cipher == rsa_fact){
    cout << "ensure_sum_equality: " << pop.champion_f()[1] << " ensure_inequality: " << pop.champion_f()[2] << " ensure_non_trivial: " << pop.champion_f()[3] << endl;
    if(pop.champion_f()[0]==0){
      int4096_t x = 1;
      int4096_t y = 1;
      for(int i=0; i<PRIME_BASE_SIZE; i++){
        x=x * (int4096_t)pow(rsa_prime_base[i],best[i]);
        y=y * (int4096_t)pow(rsa_prime_base[i],best[i+PRIME_BASE_SIZE]);
      }
      std::cout << "gcd(" << y << "-" << x << "," << ciphertext << ")=" << gcd((long long int) y-(long long int) x,int4096_t(ciphertext)) << std::endl;
      std::cout << "gcd(" << y << "+" << x << "," << ciphertext << ")=" << gcd((long long int) y+(long long int) x,int4096_t(ciphertext)) << std::endl;
    }
  }

  if(cipher == caesar || cipher == columnar || cipher == rail_fence || cipher == msub || cipher == vigenere || cipher == playfair){
    cout << plaintext.substr(0,500) << endl;
  }

  if(log_file!=""){
    extract_log(opt,log_file);
  }

  //print_usage(0); //Why are we here. We should never get this far.
}
