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
#include "helpers/custom_sga.hpp"
#include <pagmo/algorithms/nlopt.hpp>
#include <pagmo/algorithms/de1220.hpp>
#include <pagmo/algorithms/sade.hpp>
#include <pagmo/algorithms/simulated_annealing.hpp>
#include <pagmo/algorithms/nsga2.hpp>
#include <pagmo/algorithms/pso.hpp>
#include <pagmo/algorithms/gaco.hpp>
#include <pagmo/algorithms/bee_colony.hpp>
#include "helpers/cuckoo_search.hpp"
#include <pagmo/population.hpp>
#include <pagmo/problem.hpp>
#include <pagmo/types.hpp>

#define GENERATIONS 200
using namespace std;

void extract_log(pagmo::algorithm,string); //Helper function to write logs to file

const char* prog_name;

enum cipher_choice {nocipher,caesar,columnar,rail_fence,msub,vigenere,playfair,des,aes,rsa_fact,rsa_fact_alternative,rsa_rh,speck} cipher=nocipher;
enum optimization_choice {none,nlopt,ga,custom_ga,de,sa,pso,ant,bee,cuckoo} optimize=none;

void print_usage(int exit_code){ //Print help message
  cout << "Usage: " << prog_name << " options [ args ... ]\n";
  cout << " -h      --help                      Display this usage information.\n";
  cout << " -c      --cipher [cipher]           Select cipher\n";
  cout << " -o      --optimize [optimization]   Select optimization algorithm\n";
  cout << " -l      --list                      List supported ciphers and optimization algorithms.\n";
  cout << "\nExamples:\n";
  cout << " " << prog_name << " -c msub -o de substituted.txt    Use differential evolution to crack a substitution cipher\n";
  exit(exit_code);
}

void list_options(){ //Print a list of cipher/optimization options
  cout << "Supported ciphers:" << endl;
  cout << "  Caesar/Shift Cipher (caesar)" << endl;
  cout << "  Rail Fence Cipher (rail_fence)" << endl;
  cout << "  Monoalphabetic Substitution Cipher (msub)" << endl;
  cout << "  Vigenere Cipher (vigenere)" << endl;
  cout << "  Playfair Cipher (playfair)" << endl;
  cout << "  Full DES (des)" << endl;
  cout << "  Full AES (aes)" << endl;
  cout << "  RSA Factorization Problem (rsa_fact)" << endl;
  cout << "  SPECK (speck)" << endl;
  cout << "Supported optimization algorithms/schemes:" << endl;
  cout << "  Simple Genetic Algorithm (ga)" << endl;
  cout << "  Custom Genetic Algorithm (custom_ga)" << endl;
  cout << "  Differential Evolution (de)" << endl;
  cout << "  Simulated Annealing (sa)" << endl;
  cout << "  Particle Swarm Optimization (particle)" << endl;
  cout << "  Ant Colony Optimization (ant)" << endl;
  cout << "  Artificial Bee Colony Algorithm (bee)" << endl;
  cout << "  Cuckoo Search (cuckoo)" << endl;
  exit(0);
}

void select_cipher(string opt){ //Parse cipher choice
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
  else if(opt == "des"){
    cipher = des;
  }
  else if(opt == "rsa"){
    cipher = rsa_fact;
  }
  else if(opt == "rsa_alt"){
    cipher = rsa_fact_alternative;
  }
  else if(opt == "rsa_rh"){
    cipher = rsa_rh;
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

void select_optimization(string opt){ //Parse optimization choice
  if(opt == "ga"){
    optimize = ga;
  }
  else if(opt == "custom_ga"){
    optimize = custom_ga;
  }
  else if(opt == "nlopt"){
    optimize = nlopt;
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
  int population = 20; //Default population size
  string filename; //Ciphertext filename
  string ciphertext; //The ciphertext string
  string log_file = ""; //Path to the file we optionally write the log to
  pagmo::problem opt_problem; //The problem to be optimized
  pagmo::algorithm opt; //The optimization algorithm to which we pass the optimization problem
  string decrypted; //The decrypted ciphertext (=plaintext string)
  int key_length=0;

  //
  // Set floating-point precision for output
  //

  cout.setf(ios::fixed, ios::floatfield);
  cout.setf(ios::showpoint);
  cout.precision(2);

  //
  // Parse command line options
  //

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
      case 'h': // -h or --help
        print_usage(0); //Print usage/help
        break;
      case 'c': // -c or --cipher
        select_cipher(optarg); //Parse cipher choice
        break;
      case 'o': // -o or --optimize
        select_optimization(optarg); //Parse optimization choice
        break;
      case 'l': // -l or --list
        list_options(); //Print list of cipher/optimization options
        break;
      case 'p': // -p or --pop
        population = stoi(optarg); //Set population size
        break;
      case '?':
        print_usage(1);
        break;
      case 'f': // -f or --log_file
        log_file = optarg; //Set the filename to which we write the log to
        break;
      case -1:
        break;
      default:
        abort();
    }
  }
  if(optind==argc){ //If there were no command line options to parse
    print_usage(1); //Print usage/help
  }
  filename = argv[optind]; //Get ciphertext filename

  //
  // Read ciphertext from file
  //

  fstream file;
  file.open(filename, ios::in);
  if(file.is_open()){
    string line;
    while( getline(file,line)){
      ciphertext.append(line+"\n");
    }
    ciphertext.erase(ciphertext.length()-1); //Remove trailing newline
    file.close();
  }
  else{
    cout << "Cannot open '" << filename << "': No such file" << endl;
    exit(1);
  }

  //
  // Initialize optimization problem based on the chosen cipher
  //

  if(cipher == caesar){
    opt_problem = pagmo::problem{shift_generic{.ciphertext=ciphertext}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }
  else if(cipher == columnar){
    long unsigned int max_cols = 10; // Set a maximum key length of 10
    opt_problem = pagmo::problem{columnar_generic{.ciphertext=ciphertext,.max_cols=max_cols}};
    cout << "Cipher         : " << opt_problem.get_name() << "(max_cols=" << max_cols << ")" << endl;
  }
  else if(cipher == rail_fence){
    long unsigned int max_rails = ciphertext.size()/2; // Set a maximum key value of half the ciphertext size
    opt_problem = pagmo::problem{rail_fence_generic{.ciphertext=ciphertext,.max_rails=max_rails}};
    cout << "Cipher         : " << opt_problem.get_name() << "(max_rails=" << max_rails << ")" << endl;
  }
  else if(cipher == msub){
    opt_problem = pagmo::problem{msub_generic{.ciphertext=ciphertext}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }
  else if(cipher == vigenere){
    std::string stripped;
    for(auto i : ciphertext){
      if((i>='A' && i<='Z') || (i>='a' && i<='z')){
        stripped+=i;
      }
    }
    key_length = find_vigenere_key_length(stripped); //Find the most probable key length using index of coincidence
    opt_problem = pagmo::problem{vigenere_generic{.ciphertext=ciphertext,.key_length=key_length}};
    cout << "Cipher         : " << opt_problem.get_name() << "(key_length=" << key_length << ")" << endl;
  }
  else if(cipher == playfair){
    opt_problem = pagmo::problem{playfair_generic{.ciphertext=ciphertext}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }
  else if(cipher == des){
    opt_problem = pagmo::problem{des_generic{.ciphertext=ciphertext}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }
  else if(cipher == aes){
    opt_problem = pagmo::problem{aes_generic{.ciphertext=ciphertext}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }
  else if(cipher == rsa_fact){
    ciphertext.erase(std::remove(ciphertext.begin(),ciphertext.end(),'\n'),ciphertext.end());
    int4096_t n = int4096_t(ciphertext); //Parse the ciphertext as a 4096-bit integer
    opt_problem = pagmo::problem{rsa_factor{.n=n}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }
  else if(cipher == rsa_fact_alternative){
    ciphertext.erase(std::remove(ciphertext.begin(),ciphertext.end(),'\n'),ciphertext.end());
    int4096_t n = int4096_t(ciphertext); //Parse the ciphertext as a 4096-bit integer
    int4096_t upper_bound = int4096_t(sqrt(n)); //Set the upper bound
    int4096_t lower_bound = int4096_t(pow(10,ceil(log10(upper_bound.convert_to<long long int>()))-1)); //Set the lower bound
    opt_problem = pagmo::problem{rsa_factor_alternative{.n=n,.lb=lower_bound,.ub=upper_bound}};
    cout << "Cipher         : " << opt_problem.get_name() << "(" << lower_bound << " - " << upper_bound << ")" << endl;

  }
  else if(cipher == rsa_rh){
    ciphertext.erase(std::remove(ciphertext.begin(),ciphertext.end(),'\n'),ciphertext.end());
    int4096_t n = int4096_t(ciphertext);
    int4096_t upper_bound = int4096_t(sqrt(n)+1)/6;
    int bits = ceil(log2(upper_bound.convert_to<long long int>()))-1; //Find the amount of bits needed to represent the upper bound
    opt_problem = pagmo::problem{rsa_rutkowski_houghten{.n=n,.bits=bits}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }
  else if(cipher == speck){
    opt_problem = pagmo::problem{speck_generic{.ciphertext=ciphertext}};
    cout << "Cipher         : " << opt_problem.get_name() << endl;
  }

  //
  // Initialize the optimization algorithm with parameters
  //

  if(optimize == ga){
    // Default values:
    // sga(unsigned gen = 1u, double cr = .90, double eta_c = 1., double m = 0.02, double param_m = 1., unsigned param_s = 2u, std::string crossover = "exponential", std::string mutation = "polynomial", std::string selection = "tournament", unsigned seed = pagmo::random_device::next())
    opt = pagmo::algorithm{pagmo::sga(GENERATIONS,.75,1,1.0,1,5u,"single","polynomial","tournament")};
    opt.set_verbosity(2);
  }
  if(optimize == custom_ga){
    // Default values:
    // custom_sga(unsigned gen = 1u, double cr = .90, double eta_c = 1., double m = 0.02, double param_m = 1., unsigned param_s = 2u, std::string crossover = "exponential", std::string mutation = "polynomial", std::string selection = "tournament", boolean uniqueness = false, boolean pf = false,unsigned seed = pagmo::random_device::next())
    bool uniqueness=false;
    bool pf=false;
    if(cipher==msub || cipher==playfair) uniqueness=true;
    if(cipher==playfair) pf=true;
    opt = pagmo::algorithm{pagmo::custom_sga(GENERATIONS,.75,1,1.0,1,5u,"single","index_swap","tournament",uniqueness,pf)};
    opt.set_verbosity(2);
  }
  if(optimize == nlopt){
    opt = pagmo::algorithm{pagmo::nlopt("bobyqa")};
    opt.set_verbosity(1);
  }
  if(optimize == de){
    opt = pagmo::algorithm{pagmo::sade(GENERATIONS)};
    opt.set_verbosity(1);
  }
  if(optimize == sa){
    opt = pagmo::algorithm{pagmo::simulated_annealing()};
    opt.set_verbosity(1);
  }
  if(optimize == pso){
    //pagmo::algorithm opt_algo = pagmo::pso(GENERATIONS);
    opt = pagmo::algorithm{pagmo::pso(GENERATIONS)};
    opt.set_verbosity(1);
  }
  if(optimize == ant){
    opt = pagmo::algorithm{pagmo::gaco(GENERATIONS,20,1,100)};
    opt.set_verbosity(1);
  }
  if(optimize == bee){
    opt = pagmo::algorithm{pagmo::bee_colony(GENERATIONS)};
    opt.set_verbosity(1);
  }
  if(optimize == cuckoo){
    opt = pagmo::algorithm{pagmo::cuckoo_search(GENERATIONS,0.25,1.0)};
    opt.set_verbosity(1);
  }

  //
  // Print the chosen options for the run
  //

  cout << "Optimizer      : " << opt.get_name() << endl;
  cout << "Ciphertext     : " << filename << endl;
  if(log_file!="") cout << "Output file    : " << log_file << endl;
  cout << "Population size: " << population << endl;
  cout << "Generations    : " << GENERATIONS <<  endl;


  //
  // Initialize population using optimization problem and population size
  // and evolve the population according to the chosen optimization algorithm
  //

  pagmo::population pop(opt_problem,population);
  pop = opt.evolve(pop);

  //
  // Convert decision vector into a readable key representation
  //

  pagmo::vector_double best = pop.champion_x(); // Get the best candidate decision vector (key)
  string keystring = "";
  cout << "Best fitness vector, with fitness " << pop.champion_f()[0] << ":" << endl;
  cout << endl;
  for(auto i : best){ //Convert decision vector to character string or hex string
    cout.width(3);
    cout << i << ", ";
    if(int(round(i))==-1) keystring+='\0';
    if(cipher == des || cipher == aes || cipher == speck){
      keystring+=int_to_hex(int(round(i)));
    }
    else{
      keystring+=(char)('A'+round(i));
    }
  }
  cout << endl;

  if(cipher != rsa_fact || cipher != rail_fence){
    cout << "Key: " << keystring << endl;
  }

  if(cipher == caesar){ //For the caesar cipher, print the equivalent substitution key
    cout << "msub key: " << shift_to_msub_key(round(best[0])) << endl << endl;
  }
  if(cipher == msub){
    cout << "msub key: " << dv_to_msub_key(best) << endl << endl;
  }
  if(cipher == columnar){
    pagmo::vector_double col_key = columnar_key_from_dv(best);
    cout << "columnar ordering: [ ";
    for(auto i : col_key){
      cout << i << ",";
    }
    cout << " ]" << endl;
  }
  if(cipher == playfair){
    cout << "playfair key: " << dv_to_pf_key(best) << endl;
  }

  //
  // Evaluate solution
  //
  string plaintext;
  unsigned int correct=0;
  unsigned int max_correct;
  float success_rate;
  if(cipher == caesar){
    plaintext = substitute(ciphertext,shift_to_msub_key(int(round(best[0])))); //Decrypt ciphertext with the found key
    max_correct = 1;
    if(int(round(best[0]))==19){
      correct=1;
    }
  }
  if(cipher == columnar){
    plaintext = columnar_decode(ciphertext,best); //Decrypt ciphertext with the found key
    int correct_key[] = {3,1,0,2};
    pagmo::vector_double col_key = columnar_key_from_dv(best);
    for(auto i : col_key){
      cout << i << ",";
    }
    cout << endl;
    for(int i=0; i<col_key.size(); i++){ //Count correct columns
      if(correct_key[i]==col_key[i]) correct++;
    }
    max_correct = 4;
  }
  if(cipher == rail_fence){
    plaintext = rail_fence_decode(ciphertext,round(best[0])); //Decrypt ciphertext with the found key
    max_correct = 1;
    if(int(round(best[0]))==12) correct=1;
  }
  if(cipher == msub){
    plaintext = substitute(ciphertext,best);
    max_correct = 26;
    string correct_key = "CBRSTFUZNDOIKAGLWVXYPQHMEJ";
    string msub_key = dv_to_msub_key(best);
    for(int i=0; i<msub_key.size(); i++){ //Count correct characters in the found substitution key
      if(msub_key[i]==correct_key[i]) correct++;
    }
  }
  if(cipher == vigenere){
    plaintext = vigenere_decrypt(ciphertext,best,key_length); //Decrypt ciphertext with the found key
    max_correct = key_length;
    string correct_key="";
    if(key_length==3){
      correct_key="KEY";
    }
    else if(key_length==5){
      correct_key="JULES";
    }
    else if(key_length==10){
      correct_key="JULESVERNE";
    }
    for(int i=0; i<key_length; i++){ //Count correct characters in the found Vigènere key
      if(int(round(best[i]))+'A'==correct_key[i]) correct++;
    }
  }
  if(cipher == playfair){
    plaintext = playfair_decrypt(ciphertext,best); //Decrypt ciphertext with the found key
    string key = dv_to_pf_key(best);
    string correct_key = "";
    if(filename.find("JulesVerne.txt")!=-1){
      correct_key = "VERNABCDFGHIKLMOPQSTUWXYZ";
    }
    else if(filename.find("JulesVerne1.txt")!=-1){
      correct_key = "PLAYFIREXMBCDGHKNOQSTUVWZ";
    }
    max_correct = 25;
    for(int i=0; i<25; i++){ //Count correct characters in the found Playfair key
      if(key[i]==correct_key[i]) correct++;
    }
  }
  if(cipher == des){
    plaintext = des_decrypt(best,ciphertext); //Decrypt ciphertext with the found key
    array<byte,CryptoPP::DES::DEFAULT_KEYLENGTH> des_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37};
    correct = count_equal_bits(best,vector<std::byte>(des_key.begin(),des_key.end())); //Count correct bits
    max_correct = 64;
  }
  if(cipher == aes){
    plaintext = aes_decrypt(best,ciphertext); //Decrypt ciphertext with the found key
    array<byte,CryptoPP::AES::DEFAULT_KEYLENGTH> aes_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe, (byte) 0x10, (byte) 0x37, (byte) 0xde, (byte) 0xf0 };
    correct = count_equal_bits(best,vector<std::byte>(aes_key.begin(),aes_key.end())); //Count correct bits
    max_correct = 128;
  }
  if(cipher == speck){
    plaintext = speck_decrypt(best,ciphertext); //Decrypt ciphertext with the found key
    array<byte,CryptoPP::SPECK64::DEFAULT_KEYLENGTH> speck_key = { (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef, (byte) 0xba, (byte) 0xbe, (byte) 0x13, (byte) 0x37, (byte) 0xfe, (byte) 0xed, (byte) 0x7a, (byte) 0xbe };
    correct = count_equal_bits(best,vector<std::byte>(speck_key.begin(),speck_key.end())); //Count correct bits
    max_correct = 96;
  }
  if(cipher == rsa_fact || cipher == rsa_fact_alternative || cipher == rsa_rh){
    max_correct=1;
    int4096_t n(ciphertext);
    if(opt_problem.get_name()=="rsa_factor"){
      int4096_t x = 1;
      int4096_t y = 1;
      for(int i=0; i<PRIME_BASE_SIZE; i++){ //Recreate x and y from the vector representation
        x=x * (int4096_t)pow(rsa_prime_base[i],best[i]);
        y=y * (int4096_t)pow(rsa_prime_base[i],best[i+PRIME_BASE_SIZE]);
      }
      cout << "x: " << x << endl;
      cout << "y: " << y << endl;
      cout << "p: " << gcd(abs(x-y),int4096_t(ciphertext)) << endl;
      cout << "q: " << gcd(x+y,int4096_t(ciphertext)) << endl;
      if(pop.champion_f()[0]==0){ //The correct solution is only found at fitness 0
        correct=1;
      }
    }
    else if(opt_problem.get_name()=="rsa_factor_alternative"){
      int4096_t p = 1;
      for(int i=0; i<PRIME_BASE_SIZE; i++){ //Recreate p from the vector representation
        p=p * (int4096_t)pow(rsa_prime_base[i],best[i]);
      }
      int4096_t q = n/p;
      cout << p << endl;
      cout << q << endl;
      if(pop.champion_f()[0]==0){ //The correct solution is only found at fitness 0
        correct=1;
      }
    }
    else if(opt_problem.get_name()=="rsa_rutkowski_houghten"){
      int bits = best.size();
      int4096_t m = 1<<(bits);
      for(int i=0; i<bits; i++){
        m+=int(round(best[i]))<<(bits-i-1);
      }
      int4096_t p = 6*m+1;
      int4096_t q = n/p;
      if(p*q!=n){
        p = 6*m-1;
        q = n/p;
        cout << "x: " << p << endl << "y: " << q << endl;
        if(p*q==n){
          correct=1;
        }
      }
      else{
        cout << "x: " << p << endl << "y: " << q << endl;
        correct=1;
      }
    }
  }

  //
  // Print plaintext and key recovery percentage
  //

  if(cipher == caesar || cipher == columnar || cipher == rail_fence || cipher == msub || cipher == vigenere || cipher == playfair){
    cout << plaintext.substr(0,500) << endl << endl;
  }

  success_rate = float(correct)/float(max_correct);

  cout << "Correct key elements: " << correct << "/" << max_correct << endl;
  cout << "Success rate        : " << success_rate*100 << "%" << endl;

  //
  // If a log file has been chosen, log the run to the file as CSV, and success rate to a text
  // file called "Results.txt" or "Results_rsa.txt"
  //

  if(log_file!=""){
    extract_log(opt,log_file);
    fstream file;
    if(cipher == rsa_fact || cipher == rsa_fact_alternative || cipher == rsa_rh){
      file.open("Results_rsa.txt",std::ios::out | std::ios::app);
      if(file.is_open()){
        file << log_file << ": " << correct << "/" << max_correct << "=" << success_rate*100 << "%" << endl;
        file.close();
      }
      else{
        std::cout << "Cannot open '" << log_file << "': No such file" << endl;
      }
    }
    else{
      file.open("Results.txt",std::ios::out | std::ios::app);
      if(file.is_open()){
        file << log_file << ": " << correct << "/" << max_correct << "=" << success_rate*100 << "%" << endl;
        file.close();
      }
      else{
        std::cout << "Cannot open '" << log_file << "': No such file" << endl;
      }
    }
  }
}
