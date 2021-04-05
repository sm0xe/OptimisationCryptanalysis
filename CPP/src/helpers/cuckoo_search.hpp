#ifndef PAGMO_ALGORITHMS_DE_HPP
#define PAGMO_ALGORITHMS_DE_HPP
#include <string>
#include <tuple>
#include <vector>
#include <pagmo/algorithm.hpp>
#include <pagmo/population.hpp>
#include <pagmo/rng.hpp>
namespace pagmo{
  class PAGMO_DLL_PUBLIC cuckoo_search{
    public:
      cuckoo_search(unsigned gen=1u, double pa=0.25, double A=1.0);
      population evolve(population) const;
      void set_seed(unsigned);
      unsigned get_seed() const { return m_seed; }
      unsigned get_gen() const { return m_gen; }
      std::string get_name() const{
        return "Modified Cuckoo Search";
      }
      std::string get_extra_info() const;
    private:
      vector_double levy(vector_double egg, double step_size, double lambda=1.5) const;
      unsigned m_gen;
      double m_pa;
      double m_A;
      mutable detail::random_engine_type m_e;
      unsigned m_seed;
  };
}
#endif
