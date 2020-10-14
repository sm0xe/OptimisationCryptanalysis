import numpy as np
from itertools import product
from math import sqrt,floor

#n = 1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139
n = 9931 * 9973
#n = 99871 * 99991
#n = 999883 * 999979
#n = 9999883 * 9999973
#n = 99999773 * 99999989

def clamp(x):
    return min(max(x,0),n)
def fitness(point):
    if point[0]==0 or point[1]==0 or point[0]>=point[1] or abs(point[0])==abs(point[1]) or point[0]+point[1]==n or point[1]-point[0]==n: return 9e9999
    return (pow(round(point[1]),2)-pow(round(point[0]),2))%n
    #if point[1]<=point[0] or point[1]<=1 or point[0]<=1: return 9e999
    #return abs(round(point[0])*round(point[1])-n)

def update_point(x,xstar,r):
    return ((xstar[0]+r*(x[1]-xstar[1])),(xstar[1]-r*(x[0]-xstar[0])))

def spiral_optimization(kmax=100,points=5):
    r = pow(10,-3.0/kmax) #Periodic Descent Direction
    #r = pow(0.5,0.25)
    #kstar = 0
    #point_list = np.random.random((points,2))*n
    #point_list = list( product( np.linspace( 1, n, floor( sqrt(points) ) )//1, repeat=2) )
    #point_list = point_list+list(np.random.random((points-pow(floor(sqrt(points)),2),2))*n)
    lin = np.linspace(1,n,points)//1
    point_list = list(zip(lin,lin))
    fitness_list = list(map(fitness,point_list))
    best_fitness = min(fitness_list)
    best_point = point_list[np.argmin(fitness_list)]
    #prev_best_fitness = best_fitness
    for i in range(kmax):
        print("Iteration {}:".format(i))
        if points<50:
            print(point_list)
        """
        if i>=(kstar+4):
            r=1
        else:
            r=pow(0.5,0.25)
        """
        for p in range(points):
            point_list[p] = update_point(point_list[p],best_point,r)
            fitness_list[p] = fitness(point_list[p])
        if min(fitness_list)<best_fitness:
            best_fitness = min(fitness_list)
            best_point = point_list[np.argmin(fitness_list)]
            if best_fitness==0: return best_point
        print(best_point)
        print(best_fitness)
        """
        if best_fitness == prev_best_fitness:
            kstar = i
        prev_best_fitness = best_fitness
        """
    return best_point

def gcd(a,b):
    return b if a%b==0 else gcd(b,a%b)

if __name__ == "__main__":
    best_point = spiral_optimization(points=1000,kmax=10000)
    #print("Best point: {}*{}={} with fitness: {:0.2f}".format(best_point[0],best_point[1],best_point[0]*best_point[1],fitness(best_point)))
    print("Best point: ({},{}) with fitness: {:0.2f}".format(int(best_point[0]),int(best_point[1]),fitness(best_point)))
    print("gcd({}-{},{})={}".format(int(best_point[0]),int(best_point[1]),int(n),gcd(abs(int(best_point[0]-best_point[1])),n)))
    print("gcd({}+{},{})={}".format(int(best_point[0]),int(best_point[1]),int(n),gcd(int(best_point[0]+best_point[1]),n)))
