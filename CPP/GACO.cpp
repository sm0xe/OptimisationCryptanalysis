#include <cmath>
#include <initializer_list>
#include <iostream>
#include <utility>
#include "boost/multiprecision/cpp_int.hpp"

#include <pagmo/algorithm.hpp>
#include <pagmo/algorithms/gaco.hpp>
#include <pagmo/population.hpp>
#include <pagmo/problem.hpp>
#include <pagmo/types.hpp>

namespace mp = boost::multiprecision;

typedef mp::number<mp::cpp_int_backend<4096, 4096, mp::signed_magnitude, mp::unchecked, void> >  int4096_t;

using namespace pagmo;

//int4096_t n = 53*71;
int4096_t n = 997 * 967;
//int4096_t n = 9931 * 9973;
//int4096_t n = 99871 * 99991;
//int4096_t n = 999883 * 999979;
//int4096_t n = 9999883 * 9999973;
//int4096_t n = 99999773 * 99999989;

int4096_t gcd(int4096_t a, int4096_t b){
	if (!a) return b;
	return gcd(b%a,a);
}

double extended_fitness(const vector_double &dv){
	int4096_t p = (int4096_t)dv[0]*1000+(int4096_t)dv[1];
	int4096_t q = (int4096_t)dv[2]*1000+(int4096_t)dv[3];
	int4096_t fitness = (q*q)-(p*p)%n;
	return (double)fitness; //objective function
}

double ensure_sum_inequality(const vector_double &dv){
	int4096_t p = (int4096_t)dv[0]*1000+(int4096_t)dv[1];
	int4096_t q = (int4096_t)dv[2]*1000+(int4096_t)dv[3];
	return (p+q==n);
	//return 1-abs(p+q-n); //inequality constraints (x+y!=n)
}

double ensure_inequality(const vector_double &dv){
	int4096_t p = (int4096_t)dv[0]*1000+(int4096_t)dv[1];
	int4096_t q = (int4096_t)dv[2]*1000+(int4096_t)dv[3];
	return (p>=q);    //inequality constraint (p<q)
}

struct rsa_factorisation_problem {
	vector_double::size_type get_nix() const{
		return 4;
	}
	vector_double::size_type get_nec() const{
		return 2;
	}
	vector_double::size_type get_nic() const{
		return 0;
	}
	vector_double fitness(const vector_double &dv) const{
		return {
			extended_fitness(dv), //objective function
			ensure_sum_inequality(dv), //inequality constraints (x+y!=n)
			ensure_inequality(dv)    //inequality constraint (x<y)
		};
	}

	std::pair<vector_double, vector_double> get_bounds() const{
		return {{0,0,0,0},{999,999,999,999}};
	}
};

int main(){
	problem p{rsa_factorisation_problem{}};
	
	algorithm algo{gaco(10000)};

	population pop{p,1000};

	pop = algo.evolve(pop);

	std::cout << "The population: \n" << pop << std::endl;
	if(pop.champion_f()[0]==0){
		vector_double best = pop.champion_x();
		int4096_t p = (int4096_t)best[0]*1000+(int4096_t)best[1];
		int4096_t q = (int4096_t)best[2]*1000+(int4096_t)best[3];
		std::cout << "gcd(" << q << "-" << p << "," << n << ")=" << gcd(q-p,n) << std::endl;
		std::cout << "gcd(" << q << "+" << p << "," << n << ")=" << gcd(q+p,n) << std::endl;
	}
	else{
		std::cout << ":C" << std::endl;
	}
	/*
	std::cout << "Value of the objfun in (53,71): " << p.fitness({53,71})[0] << '\n';
	std::cout << "Lower bounds: [" << p.get_lb()[0] << "]\n";
	std::cout << "Upper bounds: [" << p.get_ub()[0] << "]\n\n";

	std::cout << p << '\n';
	*/
}
