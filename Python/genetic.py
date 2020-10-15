import random
import sys
import itertools

from deap import base, creator, tools
from analytics import expected_m,expected_d

def strip_specials(text):
    t = text
    for c in "'.,- ?\n()\"!/:;0123456789`":
        t = t.replace(c,"")
    return t

def random_key():
    a = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    random.shuffle(a)
    return a

def build_subs(key):
    e = {}
    d = {}
    for i in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        d[i] = i
        e[i] = i
    for c,p in zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ",key):
        d[c] = p
        e[p] = c
    return e,d

def evaluate(individual,size,base_freqs):
    if set(individual) != set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        return 9e999,
    encryption,decryption = build_subs(individual)
    chi_squared_sum = 0
    """
    phi_sum = 0.0
    english_phi_sum = 0.0668*size*(size-1)
    random_phi_sum = 0.0385*size*(size-1)
    for monogram in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        phi_sum += base_freqs[encryption[monogram]]* (base_freqs[encryption[monogram]]-1)
    if phi_sum <= random_phi_sum:
        return 0,
    else:
        return (phi_sum-random_phi_sum) / (english_phi_sum-random_phi_sum),
    """
    """
    new_digrams = {}
    size = len(strip_specials(text))
    for digram in ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=2)]:
        new_digram = encryption[digram[0]]+encryption[digram[1]]
        if new_digram in base_freqs:
            new_digrams[new_digram] = base_freqs[new_digram]
        else:
            new_digrams[new_digram] = 0
        ei = size*expected_d[digram]/100.0
        chi_squared = pow(new_digrams[new_digram]-ei,2)/ei
        chi_squared_sum=chi_squared_sum+chi_squared
    return chi_squared_sum,
    """
    chi_squared_sum = 0
    for monogram in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        ei = size*expected_m[monogram]/100.0
        chi_squared = pow(base_freqs[encryption[monogram]]-ei,2)/ei
        chi_squared_sum=chi_squared_sum+chi_squared
    return chi_squared_sum,

creator.create("FitnessMin", base.Fitness, weights=(-1.0,))
creator.create("Individual", list, fitness=creator.FitnessMin)

IND_SIZE = 26

toolbox = base.Toolbox()
toolbox.register("attribute", random_key)
toolbox.register("individual", tools.initIterate, creator.Individual, toolbox.attribute)
toolbox.register("population", tools.initRepeat, list, toolbox.individual)

text = ""
with open(sys.argv[1],"r") as f:
    text_file = f.read()
    correct_key,text = text_file.split("\n")[0],"".join(text_file.split("\n")[1:])

def monogram_frequency(text):
    monograms = {}
    for i in range(len(text)):
        monogram = strip_specials(text[i].upper())
        if len(monogram)==1:
            if monogram not in monograms:
                monograms[monogram] = 0
            monograms[monogram] = monograms[monogram]+1
    return monograms

def digram_frequency(text):
    digrams = {}
    for i in range(len(text)):
        digram = strip_specials(text[i:i+2].upper())
        if len(digram)==2:
            if digram not in digrams:
                digrams[digram] = 0
            digrams[digram] = digrams[digram]+1
    return digrams

orig_monograms = monogram_frequency(text)
orig_digrams = digram_frequency(text)

toolbox.register("mate", tools.cxTwoPoint)
toolbox.register("mutate", tools.mutShuffleIndexes,indpb=0.2)
toolbox.register("select", tools.selTournament, tournsize=50)
toolbox.register("evaluate", evaluate, size=len(strip_specials(text)), base_freqs=orig_monograms)

def main():
    pop = toolbox.population(n=50)
    CXPB, MUTPB, NGEN = 0.5 , 0.5 , 2000

    fitnesses = list(map(toolbox.evaluate, pop))
    for ind in pop:
        print(ind)
    for ind, fit in zip(pop, fitnesses):
        ind.fitness.values = fit

    for g in range(NGEN):
        offspring = toolbox.select(pop, len(pop))
        offspring = list(map(toolbox.clone, offspring))

        for child1, child2 in zip(offspring[::2], offspring[1::2]):
            if random.random() < CXPB:
                toolbox.mate(child1, child2)
                del child1.fitness.values
                del child2.fitness.values

        for mutant in offspring:
            if random.random() < MUTPB:
                toolbox.mutate(mutant)
                del mutant.fitness.values

        invalid_ind = [ind for ind in offspring if not ind.fitness.valid]
        fitnesses = list(map(toolbox.evaluate, invalid_ind))
        for ind,fit in zip(invalid_ind, fitnesses):
            ind.fitness.values = fit

        pop[:] = offspring
    print("Done")
    for ind,fit in sorted([("".join(i),toolbox.evaluate(i)[0]) for i in pop],key=lambda x: -x[1]):
        print("{}: {}".format(ind,fit))
    best_key = min([("".join(i),toolbox.evaluate(i)[0]) for i in pop],key=lambda x: x[1])[0]
    encryption,decryption = build_subs(best_key)
    computed_encrypt = ""
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        print(encryption[c],end="")
        computed_encrypt+=encryption[c]
    print()
    print(correct_key)
    sum=0
    for computed,correct in zip(computed_encrypt,correct_key):
        if computed == correct:
            sum = sum + 1
            print(computed,end="")
        else:
            print(" ",end="")
    print("\n{}/26".format(sum))
    return pop

if __name__ == "__main__":
    main()
