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
    typedef std::tuple<unsigned,unsigned long long,double,double,double,double,double> log_line_type;
    typedef std::vector<log_line_type> log_type;
    public:
      cuckoo_search(unsigned gen=1u, double pa=0.25, double A=10.0);
      population evolve(population) const;
      void set_seed(unsigned);
      unsigned get_seed() const { return m_seed; }
      unsigned get_gen() const { return m_gen; }
      unsigned get_verbosity() { return m_verbosity; }
      void set_verbosity(unsigned level){
        m_verbosity = level;
      }
      std::string get_name() const{
        return "Modified Cuckoo Search";
      }
      std::string get_extra_info() const;
      const log_type &get_log() const{
        return m_log;
      }
    private:
      vector_double levy(vector_double egg, unsigned int dim, vector_double lower_bounds, vector_double upper_bounds, double step_size, double lambda=1.5) const;
      unsigned m_gen;
      double m_pa;
      double m_A;
      unsigned m_verbosity;
      mutable detail::random_engine_type m_e;
      unsigned m_seed;
      mutable log_type m_log;
  };
}
#endif
