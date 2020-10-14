#!/bin/env python3
import sys
import copy
import itertools
from scipy.optimize import linear_sum_assignment
from analytics import expected_m,expected_d,statistics

def strip_specials(s):
    t = s
    for c in "'.,- ?\n()\"!/:;0123456789`":
        t = t.replace(c,"")
    return t

def print_frequencies(freqs):
    for c in sorted(freqs.keys()):
        print("{}: {}".format(c,freqs[c]))

def calculate_weights(freqs,size,r=1):
    m = dict()
    product = ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=r)]
    for c in sorted(freqs.keys()):
        n = list()
        for e in product:
            if r==1:
                ei = size*expected_m[e]/100.0
            if r==2:
                ei = size*expected_d[e]/100.0
            chi_squared = pow(freqs[c] - ei,2) / ei * 100
            n.append(chi_squared)
        m[c]=n

    #print_graph(m,r=r)
    return m

def print_graph(graph,row_ind=[],col_ind=[],cor_row_ind=[],cor_col_ind=[],r=1):
    print("  |",end="")
    product = ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=r)]
    for e in product:
        print("{:>8}|".format(e),end="")
    print("")
    for i,c in enumerate(sorted(graph.keys())):
        print("{} |".format(c),end="")
        for j in range(len(product)):
            if len(row_ind)>0:
                if (i,j) in zip(row_ind,col_ind):
                    print(u"\u001b[31m",end="")
                if (i,j) in zip(cor_row_ind,cor_col_ind):
                    print(u"\u001b[32m",end="")
            print("{0:>8.0f}|".format(graph[c][j]),end="")
            if len(row_ind)>0 and ((i,j) in zip(row_ind,col_ind) or (i,j) in zip(cor_row_ind,cor_col_ind)):
                print(u"\u001b[0m",end="")
        print("\n",end="")
    print("\n",end="")

def graph_to_matrix(graph):
    return [graph[i] for i in sorted(graph.keys())]

def analyse(text):
    monograms,digrams,trigrams = statistics(text)
    print_frequencies(monograms)
    print_frequencies(digrams)
    #print_frequencies(trigrams)
    return (calculate_weights(monograms,len(strip_specials(text)),r=1),monograms,digrams)

def check_key(encryption,correct_key):
    computed_key = "".join([encryption[c] if c in encryption else " " for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"])
    print("Alphabet   : ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    print("Found key  : {}".format(computed_key))
    print("Correct key: {}".format(correct_key))
    print("           : ",end="")
    correct = 0
    for i in range(26):
        if computed_key[i]== correct_key[i]:
            print(computed_key[i],end="")
            correct = correct + 1
        else:
            print(" ",end="")
    print("\nSuccess rate: {}/26 = {:0.2f}%".format(correct,correct*100/26))
if __name__ == "__main__":
    with open(sys.argv[1],"r") as f:
        textfile = f.read()
        correct_key,text = textfile.split("\n")[0],"\n".join(textfile.split("\n")[1:])
        print("With spaces and special characters:")
        g,m,d = analyse(strip_specials(text))
        matrix_g = graph_to_matrix(g)
        row_ind,col_ind = linear_sum_assignment(matrix_g)
        #print_graph(g,row_ind,col_ind)
        decryption = {}
        encryption = {}
        chisum = 0
        for i,j in zip(row_ind,col_ind):
            c = sorted(g.keys())[i]
            p = ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=1)][j]
            decryption[c] = p
            encryption[p] = c
            print("{} -> {}".format(c,p))
            chisum = chisum + matrix_g[i][j]
        for c in text:
            if c.upper() in decryption:
                if c.isupper():
                    print(decryption[c],end="")
                else:
                    print(decryption[c.upper()].lower(),end="")
            else:
                print(c,end="")
        print("\n",end="")
        cor_col_ind = list(range(0,26))
        cor_row_ind = [0]*26
        for i in range(26):
            cor_row_ind[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".index(correct_key[i])
        print_graph(g,row_ind,col_ind,cor_row_ind,cor_col_ind)
        check_key(encryption,correct_key)
        print("Chi-squared: {}".format(chisum))

        print("Simple naive solution:")
        for c,p in zip(sorted(m.items(), key=lambda item: -item[1]),sorted(expected_m.items(),key=lambda item: -item[1])):
            print("{}->{}".format(p[0],c[0]))
            encryption[p[0]] = c[0]
        check_key(encryption,correct_key)

        print("Naive digrams:")
        encryption={}
        for c,p in zip(sorted(d.items(), key=lambda item: -item[1]),sorted(expected_d.items(),key=lambda item: -item[1])):
            digram_c = c[0]
            digram_p = p[0]
            if digram_p[0] in encryption and digram_c[0] is not encryption[digram_p[0]]:
                continue
            if digram_p[1] in encryption and digram_c[1] is not encryption[digram_p[1]]:
                continue
            if digram_p[0] not in encryption:
                if digram_c[0] in encryption.values():
                    print("Conflict: {}->{}".format(digram_p,digram_c))
                    new = matrix_g[ord(digram_c[0])-65][ord(digram_p[0])-65]
                    for char in encryption:
                        if encryption[char] is digram_c[0]: bleh=char
                    existing = matrix_g[ord(digram_c[0])-65][ord(bleh)-65]
                    #print("existing: {}\nnew: {}".format(existing,new))
                    if new<existing:
                        print("Removing {}->{}".format(bleh,encryption[bleh]))
                        del encryption[bleh]
                        encryption[digram_p[0]] = digram_c[0]
                        print("{}->{}".format(digram_p[0],digram_c[0]))
                    continue
                    continue
                else:
                    encryption[digram_p[0]] = digram_c[0]
                print("{}->{}".format(digram_p[0],digram_c[0]))
            if digram_p[1] not in encryption:
                if digram_c[1] in encryption.values():
                    print("Conflict: {}->{}".format(digram_p,digram_c))
                    new = matrix_g[ord(digram_c[1])-65][ord(digram_p[1])-65]
                    for char in encryption:
                        if encryption[char] is digram_c[1]: bleh=char
                    existing = matrix_g[ord(digram_c[1])-65][ord(bleh)-65]
                    #print("existing: {}\nnew: {}".format(existing,new))
                    if new<existing:
                        print("Removing {}->{}".format(bleh,encryption[bleh]))
                        del encryption[bleh]
                        encryption[digram_p[1]] = digram_c[1]
                        print("{}->{}".format(digram_p[1],digram_c[1]))
                    continue
                else:
                    encryption[digram_p[1]] = digram_c[1]
                print("{}->{}".format(digram_p[1],digram_c[1]))

        check_key(encryption,correct_key)
        #print("Without spaces and special characters:")
        #analyse(strip_specials(text))
