#!/bin/env python3
import sys
import heapq
import itertools
from random import shuffle
from math import factorial
from analytics import expected_m,expected_d,expected_t,statistics

explored = set()
size = 0
m = {}
d = {}
t = {}
#di_product = ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=2)]
#tri_product = ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=3)]

def fitness(key):
    chi_squared_sum = 0
    weightings = [1.0,1.0,0.0]
    encryption = {}
    decryption = {}
    for c,p in zip(key,"ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        encryption[p] = c
        decryption[c] = p
    for monogram in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        ei = size*expected_m[monogram]/100.0
        if encryption[monogram] in m:
            chi_squared = pow(m[encryption[monogram]]-ei,2)/ei
        else:
            chi_squared = ei
        chi_squared_sum += chi_squared*weightings[0]
    for digram in d.keys():
        #encrypted_digram = encryption[digram[0]]+encryption[digram[1]]
        decrypted_digram = decryption[digram[0]]+decryption[digram[1]]
        ei = size*expected_d[decrypted_digram]/100.0
        if digram in d:
            chi_squared = pow(d[digram] - ei, 2) / ei
        else:
            chi_squared = ei
        chi_squared_sum += chi_squared*weightings[1]
    if weightings[2]!=0:
        for trigram in t.keys():
            #encrypted_trigram = encryption[trigram[0]]+encryption[trigram[1]]+encryption[trigram[2]]
            decrypted_trigram = decryption[trigram[0]]+decryption[trigram[1]]+decryption[trigram[2]]
            if decrypted_trigram in expected_t:
                ei = size*expected_t[decrypted_trigram]/100.0
            else:
                continue
            if trigram in t:
                chi_squared = pow(t[trigram]-ei,2)/ei
            else:
                chi_squared = ei
            chi_squared_sum += chi_squared*weightings[2]
    return chi_squared_sum

def simple_permutations(key):
    new_cands = []
    for i in range(len(key)):
        for j in range(i+1,len(key)):
            new_cand = list(key)
            new_cand[i],new_cand[j]= new_cand[j],new_cand[i]
            if "".join(new_cand) not in explored:
                new_cands.append("".join(new_cand))
    return new_cands

def greedy_search(cand_key):
    count = 0
    best_fitness = fitness(cand_key)
    best_key = cand_key
    queue = []
    heapq.heappush(queue,(best_fitness,cand_key))
    while queue:
        fit,cur_key = heapq.heappop(queue)
        if fit>best_fitness:
            """
            if not queue and best_fitness>10000:
                cur_key = list(cur_key)
                shuffle(cur_key)
                cur_key = "".join(cur_key)
                fit = fitness(cur_key)
                print("I don't want it to end, so I'll push {} ({}) :(".format(cur_key,fit))
                heapq.heappush(queue,(fit,cur_key))
            else:
                """
            continue
        print("At {} ({})".format(cur_key,fit))
        for new_cand in simple_permutations(cur_key):
            if new_cand not in explored:
                new_cand_fitness = fitness(new_cand)
                count = count+1
                if new_cand_fitness<=best_fitness:
                    heapq.heappush(queue,(new_cand_fitness,new_cand))
                    best_fitness = new_cand_fitness
                    best_key = new_cand
                explored.add(new_cand)

    print("Explored {} keys".format(count))
    return best_key,best_fitness

if __name__ == "__main__":
    with open(sys.argv[1],"r") as f:
        textfile = f.read()
        correct_key,text = textfile.split("\n")[0],"\n".join(textfile.split("\n")[1:])
        size = len(text)
        m,d,t = statistics(text)
        print(m)
        #cand_key = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        #shuffle(cand_key)
        cand_key=""
        encryption={}
        for c,p in zip(sorted(m.items(), key=lambda item: -item[1]),sorted(expected_m.items(),key=lambda item: -item[1])):
            encryption[p[0]]= c[0]
        for p in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            cand_key+=encryption[p]
        found_key,fit = greedy_search("".join(cand_key))

        decryption = {}
        for c,p in zip(found_key,"ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
            decryption[c] = p
        for c in text:
            if c.upper() in decryption:
                if c.isupper():
                    print(decryption[c],end="")
                else:
                    print(decryption[c.upper()].lower(),end="")
            else:
                print(c,end="")
        print("\n",end="")
        print("Found key {} with fitness {}".format(found_key,fit))
        print("Correct key is {} with fitness {}".format(correct_key,fitness(correct_key)))
        print("Alphabet:    ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        print("Found key:   {}".format(found_key))
        print("Correct_key: {}".format(correct_key))
        print("           : ",end="")
        correct = 0
        for i in range(26):
            if found_key[i] == correct_key[i]:
                print(found_key[i],end="")
                correct = correct+1
            else:
                print(" ",end="")
        print("\nSuccess rate: {}/26 = {:0.2f}%".format(correct,correct*100/26))
