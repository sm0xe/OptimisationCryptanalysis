#include <iostream>
#include <fstream>
#include <pagmo/algorithm.hpp>
#include <pagmo/algorithms/sga.hpp>
#include <pagmo/algorithms/de1220.hpp>
#include <pagmo/algorithms/sade.hpp>
#include <pagmo/algorithms/simulated_annealing.hpp>
#include <pagmo/algorithms/pso.hpp>
#include <pagmo/algorithms/gaco.hpp>
#include <pagmo/algorithms/bee_colony.hpp>
#include "cuckoo_search.hpp"

#define PAD_SGA
#define GENERATIONS 200

void extract_log(pagmo::algorithm algo,std::string log_file){
  std::fstream file;
  file.open(log_file,std::ios::out);
  file.setf(std::ios::fixed, std::ios::floatfield);
  file.setf(std::ios::showpoint);
  file.precision(2);
  if(file.is_open()){
    file << "Gen,Best" << std::endl;

    if(algo.is<pagmo::sga>()){
      auto m_log = algo.extract<pagmo::sga>()->get_log();
      #ifdef PAD_SGA
      unsigned int gen=0;
      double prev_best=1e10;
      #endif
      for(auto log_line : m_log){
        unsigned int line_gen;
        double best,improvement;
        std::tie(line_gen,std::ignore,best,improvement) = log_line;
        #ifdef PAD_SGA
        gen++;
        for(;gen<line_gen;gen++){
          file << gen << "," << prev_best << std::endl;
        }
        prev_best=best-improvement;
        #endif
        file << line_gen << "," << best << std::endl;
      }
#ifdef PAD_SGA
      while(gen<GENERATIONS){
        gen++;
        file << gen << "," << prev_best << std::endl;
      }
#endif
    }
    else if(algo.is<pagmo::de1220>()){
      auto m_log = algo.extract<pagmo::de1220>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        double best;
        std::tie(gen,std::ignore,best,std::ignore,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << std::endl;
      }
    }
    else if(algo.is<pagmo::sade>()){
      auto m_log = algo.extract<pagmo::sade>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        double best;
        std::tie(gen,std::ignore,best,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << std::endl;
      }
    }
    else if(algo.is<pagmo::simulated_annealing>()){
      auto m_log = algo.extract<pagmo::simulated_annealing>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        double best;
        std::tie(gen,std::ignore,best,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << std::endl;
      }
    }
    else if(algo.is<pagmo::pso>()){
      auto m_log = algo.extract<pagmo::pso>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        double best;
        std::tie(gen,std::ignore,best,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << std::endl;
      }
    }
    else if(algo.is<pagmo::gaco>()){
      auto m_log = algo.extract<pagmo::gaco>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        double best;
        std::tie(gen,std::ignore,best,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << std::endl;
      }
    }
    else if(algo.is<pagmo::bee_colony>()){
      auto m_log = algo.extract<pagmo::gaco>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        double best;
        std::tie(gen,std::ignore,best,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << std::endl;
      }
    }
    else if(algo.is<pagmo::cuckoo_search>()){
      auto m_log = algo.extract<pagmo::cuckoo_search>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        double best;
        std::tie(gen,std::ignore,best,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << std::endl;
      }
    }
    else{
      std::cout << "Could not detect algorithm" << std::endl;
    }
    file.close();
  }
  else{
    std::cout << "Cannot open '" << log_file << "': No such file" << std::endl;
  }
}
