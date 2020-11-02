#include <cmath>
#include <initializer_list>
#include <iostream>
#include <utility>

#include <pagmo/algorithm.hpp>
#include <pagmo/algorithms/gaco.hpp>
#include <pagmo/population.hpp>
#include <pagmo/problem.hpp>
#include <pagmo/types.hpp>

using namespace pagmo;

//const long long int n = 53*71;
//const long long int n = 997 * 967;
const long long int n = 9931 * 9973;
//const long long int n = 99871 * 99991;
//const long long int n = 999883 * 999979;
//const long long int n = 9999883 * 9999973;
//const long long int n = 99999773 * 99999989;
//
long long int gcd(long long int a, long long int b){
	if (!a) return b;
	return gcd(b%a,a);
}

struct problem_v0 {
	vector_double::size_type get_nix() const{
		return 2;
	}
	vector_double::size_type get_nec() const{
		return 0;
	}
	vector_double::size_type get_nic() const{
		return 2;
	}
	vector_double fitness(const vector_double &dv) const{
		return {
			//abs(dv[0]*dv[1]-n), //objective function
			(long long int)(pow(dv[1],2)-pow(dv[0],2))%n, //objective function
			//dv[0]-int(dv[0]), dv[1]-int(dv[1]), //equality constraints (ensure integers)
			0.01-abs(dv[0]+dv[1]-n), //inequality constraints (x+y!=n)
			dv[0]-dv[1]+0.01    //inequality constraint (x>y)
		};
	}

	std::pair<vector_double, vector_double> get_bounds() const{
		return {{2.,2.},{n,n}};
	}
};

int main(){
	problem p{problem_v0{}};
	
	algorithm algo{gaco(1000000)};

	population pop{p,200};

	pop = algo.evolve(pop);

	std::cout << "The population: \n" << pop << std::endl;
	if(pop.champion_f()[0]==0){
		vector_double best = pop.champion_x();
		std::cout << "gcd(" << best[1] << "-" << best[0] << "," << n << ")=" << std::gcd((long long int) best[1]-(long long int) best[0],n) << std::endl;
		std::cout << "gcd(" << best[1] << "+" << best[0] << "," << n << ")=" << std::gcd((long long int) best[1]+(long long int) best[0],n) << std::endl;
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
