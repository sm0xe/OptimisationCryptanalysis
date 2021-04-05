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

//https://doi.org/10.1016/j.chaos.2011.06.004

namespace pagmo{
  bool compare_fitness(const std::pair<vector_double,vector_double>& x, const std::pair<vector_double,vector_double>& y){
    /*
    if(x.second[0] == y.second[0]){
      return x.second[1] < y.second[1];
    }
    return x.second[0] < y.second[0];
    */
    double x_prod = 1.0;
    double y_prod = 1.0;
    for(int i=0; i<sizeof(x.second)/sizeof(x.second[0]); i++){
      x_prod*=x.second[i];
      y_prod*=y.second[i];
    }
    return x_prod < y_prod;
  }
  vector_double cuckoo_search::levy(vector_double egg,double step_size, double lambda) const{
    double sigma = pow(gamma(1+lambda)*sin(3.141592*lambda/2)/gamma((1+lambda)/2)*pow(2,(lambda-1)/2),1.0/lambda);
    std::normal_distribution<double> u_rand(0,sigma);
    std::normal_distribution<double> v_rand(0,1);
    vector_double new_egg = egg;
    for(int i=0; i<sizeof(egg)/sizeof(egg[0]); i++){
      new_egg[i] = egg[i] + step_size * u_rand(m_e) / pow(fabs(v_rand(m_e)),1.0/lambda);
    }
    return new_egg;
  }

  cuckoo_search::cuckoo_search(unsigned gens, double pa, double A) : m_gen(gens), m_pa(pa), m_A(A){
  }

  population cuckoo_search::evolve(population pop) const{
    const auto &prob = pop.get_problem();
    auto dim = prob.get_nx();
    const auto bounds = prob.get_bounds();
    const auto &lb = bounds.first;
    const auto &ub = bounds.second;
    const long unsigned int NP = pop.size();
    auto prob_f_dimension = prob.get_nf();

    auto popx = pop.get_x();
    auto fit = pop.get_f();

    std::vector<std::pair<vector_double,vector_double>> pop_wrapper;
    for(int i=0; i<NP; i++){
      pop_wrapper.push_back(make_pair(popx[i],fit[i]));
    }

    int ab_count = floor(m_pa*NP);
    std::uniform_int_distribution<vector_double::size_type> rand_idx(0u,NP-1u);
    std::uniform_int_distribution<vector_double::size_type> rand_top_idx(0u,NP-1u-ab_count);

    for(decltype(m_gen) gen=1u; gen<=m_gen; ++gen){
      std::sort(pop_wrapper.begin(),pop_wrapper.end(), compare_fitness); //Sort by fitness
      //std::array<std::vector<array,dim>> new_nests(ab_count);
      auto step_size = m_A/sqrt(gen); //Calculate Levy flight step size
      for(int i=ab_count-1; i>=0; i--){ //For all nests to be abandoned
        auto new_nest = levy(pop_wrapper[rand_idx(m_e)].first,step_size,1.5); //Perform Levy flight from xi to generate new egg xk
        pop_wrapper[NP-i] = make_pair(new_nest,prob.fitness(new_nest)); //Abandon nest and insert new egg
      }

      step_size = m_A/pow(gen,2); //Calculate new Levy flight step size
      for(int i=0; i<NP-ab_count; i++){ //For all of the top nests do
        int rand_top_nest_idx = rand_top_idx(m_e); //Pick another nest xj from the top nests at random
        if(i==rand_top_nest_idx){ //If xi=xj then
          auto new_egg = levy(pop_wrapper[i].first,step_size,1.5); //Generate new egg xk with Levy flight
          auto new_egg_fit = prob.fitness(new_egg); //Calculate fitness of new egg xk
          auto rand_nest_idx = rand_idx(m_e); //Choose a random nest l from all nests
          if(new_egg_fit <= pop_wrapper[rand_nest_idx].second){ //If f(xk)<=f(xj) do
            pop_wrapper[rand_nest_idx] = make_pair(new_egg,new_egg_fit);
          }
        }
        else{
          auto dx = 0;
          auto rand_top_nest = pop_wrapper[rand_top_nest_idx].first;
          auto rand_top_nest_fit = pop_wrapper[rand_top_nest_idx].second;
          vector_double move_vector(dim);
          for(int j=0; j<dim; j++){ //Calculate distance and movement vector in the same loop
            dx += pow(rand_top_nest[j]-pop_wrapper[i].first[j],2);
            if(pop_wrapper[i].second<rand_top_nest_fit){
              move_vector[j]=pop_wrapper[i].first[j]-rand_top_nest[j];
            }
            else{
              move_vector[j]=rand_top_nest[j]-pop_wrapper[i].first[j];
            }
          }
          dx = sqrt(dx)/1.618;
          vector_double xk(dim);
          for(int j=0; j<dim; j++){ //Move dx from worst to best
            if(pop_wrapper[i].second<rand_top_nest_fit){
              xk[j] = rand_top_nest[j]+(move_vector[j]*dx);
            }
            else{
              xk[j] = pop_wrapper[i].first[j]+(move_vector[j]*dx);
            }
          }
          auto new_egg_fit = prob.fitness(xk);
          if(new_egg_fit<=pop_wrapper[i].second){
            pop_wrapper[i] = make_pair(xk,new_egg_fit);
          }
        }
      }

    }
    for(int i=0; i<NP; i++){
      auto egg = pop_wrapper[i];
      pop.set_xf(i,egg.first,egg.second);
    }
    return pop;
  }

  void cuckoo_search::set_seed(unsigned seed){
    m_e.seed(seed);
    m_seed = seed;
  }
  std::string cuckoo_search::get_extra_info() const{
    return "\tGenerations: " + std::to_string(m_gen) + "\n\tParameter P_a: " + std::to_string(m_pa)
      + "\n\tParameter A: " + std::to_string(m_A) + "\n\tSeed: " + std::to_string(m_seed);
  }
}
