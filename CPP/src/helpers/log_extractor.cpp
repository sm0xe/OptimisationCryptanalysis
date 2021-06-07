#include <iostream>
#include <fstream>
#include <pagmo/algorithm.hpp>
#include <pagmo/algorithms/sga.hpp>
#include "custom_sga.hpp"
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
  file.open(log_file,std::ios::out | std::ios::trunc);
  file.setf(std::ios::fixed, std::ios::floatfield);
  file.setf(std::ios::showpoint);
  file.precision(2);
  if(file.is_open()){
    file << "Gen,Best,Fevals" << std::endl;

    if(algo.is<pagmo::sga>() || algo.is<pagmo::custom_sga>()){
      std::vector<pagmo::sga::log_line_type> m_log;
      if(algo.is<pagmo::sga>()) m_log = algo.extract<pagmo::sga>()->get_log();
      if(algo.is<pagmo::custom_sga>()) m_log = algo.extract<pagmo::custom_sga>()->get_log();
      #ifdef PAD_SGA
      unsigned int gen=0;
      unsigned int pop_size=0;
      unsigned int fevals;
      double prev_best=1e10;
      #endif
      for(auto log_line : m_log){
        unsigned int line_gen;
        unsigned int line_fevals;
        double best,improvement;
        std::tie(line_gen,line_fevals,best,improvement) = log_line;
        if(pop_size==0) pop_size=line_fevals;
        #ifdef PAD_SGA
        gen++;
        fevals+=pop_size;
        for(;gen<line_gen;gen++,fevals+=pop_size){
          file << gen << "," << prev_best << "," << fevals << std::endl;
        }
        prev_best=best-improvement;
        #endif
        file << line_gen << "," << best << "," << line_fevals << std::endl;
        fevals = line_fevals;
      }
#ifdef PAD_SGA
      while(gen<GENERATIONS){
        gen++;
        fevals+=pop_size;
        file << gen << "," << prev_best << "," << fevals << std::endl;
      }
#endif
    }
    else if(algo.is<pagmo::de1220>()){
      auto m_log = algo.extract<pagmo::de1220>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        unsigned int fevals;
        double best;
        std::tie(gen,fevals,best,std::ignore,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << "," << fevals << std::endl;
      }
    }
    else if(algo.is<pagmo::sade>()){
      auto m_log = algo.extract<pagmo::sade>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        unsigned int fevals;
        double best;
        std::tie(gen,fevals,best,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << "," << fevals << std::endl;
      }
    }
    else if(algo.is<pagmo::simulated_annealing>()){
      auto m_log = algo.extract<pagmo::simulated_annealing>()->get_log();
      for(auto log_line : m_log){
        unsigned int fevals;
        double best;
        std::tie(fevals,std::ignore,best,std::ignore,std::ignore) = log_line;
        file << "," << best << "," << fevals << std::endl;
      }
    }
    else if(algo.is<pagmo::pso>()){
      auto m_log = algo.extract<pagmo::pso>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        unsigned int fevals;
        double best;
        std::tie(gen,fevals,best,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << "," << fevals << std::endl;
      }
    }
    else if(algo.is<pagmo::gaco>()){
      auto m_log = algo.extract<pagmo::gaco>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        unsigned int fevals;
        double best;
        std::tie(gen,fevals,best,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << "," << fevals << std::endl;
      }
    }
    else if(algo.is<pagmo::bee_colony>()){
      auto m_log = algo.extract<pagmo::bee_colony>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        unsigned int fevals;
        double best;
        std::tie(gen,fevals,best,std::ignore) = log_line;
        file << gen << "," << best << "," << fevals << std::endl;
      }
    }
    else if(algo.is<pagmo::cuckoo_search>()){
      auto m_log = algo.extract<pagmo::cuckoo_search>()->get_log();
      for(auto log_line : m_log){
        unsigned int gen;
        unsigned int fevals;
        double best;
        std::tie(gen,fevals,best,std::ignore,std::ignore,std::ignore,std::ignore) = log_line;
        file << gen << "," << best << "," << fevals << std::endl;
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
