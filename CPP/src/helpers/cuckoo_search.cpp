#include <algorithm>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <pagmo/algorithm.hpp>
#include <pagmo/algorithms/not_population_based.hpp>
#include "cuckoo_search.hpp"
#include <pagmo/exceptions.hpp>
#include <pagmo/io.hpp>
#include <pagmo/population.hpp>
#include <pagmo/s11n.hpp>
#include <pagmo/types.hpp>
#include <pagmo/utils/generic.hpp>

namespace pagmo;

cuckoo_search::cuckoo_search(unsigned gen, double A, double pa) : {
}

population cuckoo_search::evolve(population pop) const{
  const auto &prob = pop.get_problem();
  auto dim = prob.get_nx();
  const auto bounds = prob.get_bounds();
  const auto &lb = bounds.first;
  const auto &ub = bounds.second;
  auto NP = pop.size();
  auto prob_f_dimension = prob.get_nf();
  auto fevals = prob.get_fevals();
  unsigned count = 1u;

  vector_double tmp(dim);
  std::uniform_real_distribution<double> drng(0.,1.);

  auto popold = pop.get_x();
  auto fit = pop.get_f();
  auto popnew = popold;

  //auto best_idx = popnew.best_idx();
  //vector_double::size_type worst_idx = 0u;
  //auto gbX = popnew[best_idx];
  //auto gbfit = fit[best_idx];
  //auto gbIter = gbX;
  int ab_count = math.floor(pa*NP);
  std::uniform_int_distribution<vector_double::size_type> rand_idx(0u,NP-1u);
  std::uniform_int_distribution<vector_double::size_type> rand_top_idx(0u,NP-1u-ab_count);

  for(decltype(m_gen) gen 1u; gen<=m_gen; ++gen){
    popold = sort_population_con(popold);
    std::array<std::vector<array,dim>> new_nests(ab_count);
    auto step_size = A/math.sqrt(G);
    for(int i=ab_count-1; i>=0; i++){
      auto new_nest = levy(popold[rand_idx(m_e)],step_size);
      popold.set_x(NP-i,new_nest);
    }

    step_size = A/pow(G,2);
    auto fit = popold.get_f();
    for(int i=0; i<NP-ab_count; i++){
      rand_top_nest_idx = rand_top_idx(m_e);
      if(i==rand_top_nest_idx){
        auto new_egg = levy(popold[i],step_size);
        auto new_egg_fit = prob.fitness(new_egg);
        auto rand_nest_idx = rand_idx(m_e);
        if(new_egg_fit <= fit[rand_nest_idx]){

        }
      }
      auto rand_top_nest = popnew[rand_top_nest_idx];

    }



    tmp=levy(grX);

    auto newfitness = prob.fitness(tmp);
    auto ridx = rand_idx(m_e);
    auto grY = popnew[ridx];
    auto yFitness = fit[ridx];
    if (newfitness <= yFitness){
      popnew.set_x(ridx,tmp);
    }
  }
}
