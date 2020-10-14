import itertools
expected_m = {}
expected_d = {}
expected_t = {}
with open("english_monograms.txt","r") as f:
    N = 0
    for line in f.readlines():
        key,count = line.split(" ")
        expected_m[key] = int(count)
        N = N+int(count)
    for key in ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=1)]:
        expected_m[key] = float(expected_m[key])/N*100
with open("english_bigrams.txt","r") as f:
    N = 0
    for line in f.readlines():
        key,count = line.split(" ")
        expected_d[key] = int(count)
        N = N+int(count)
    for key in ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=2)]:
        expected_d[key] = float(expected_d[key])/N*100
with open("english_trigrams.txt","r") as f:
    N = 0
    for line in f.readlines():
        key,count = line.split(" ")
        expected_t[key] = int(count)
        N = N+int(count)
    for key in ["".join(i) for i in itertools.product("ABCDEFGHIJKLMNOPQRSTUVWXYZ",repeat=3)]:
        if(key in expected_t):
            expected_t[key] = float(expected_t[key])/N*100
#expected = {
#    "A": 8.04,
#    "B": 1.48,
#    "C": 3.34,
#    "D": 3.82,
#    "E": 12.49,
#    "F": 2.40,
#    "G": 1.87,
#    "H": 5.05,
#    "I": 7.57,
#    "J": 0.16,
#    "K": 0.54,
#    "L": 4.07,
#    "M": 2.51,
#    "N": 7.23,
#    "O": 7.64,
#    "P": 2.14,
#    "Q": 0.12,
#    "R": 6.28,
#    "S": 6.51,
#    "T": 9.28,
#    "U": 2.73,
#    "V": 1.05,
#    "W": 1.68,
#    "X": 0.23,
#    "Y": 1.66,
#    "Z": 0.09,
#    "AA": 0.003,
#    "AB": 0.23,
#    "AC": 0.448,
#    "AD": 0.368,
#    "AE": 0.012,
#    "AF": 0.074,
#    "AG": 0.205,
#    "AL": 1.09,
#    "AN": 1.99,
#    "AR": 1.07,
#    "AS": 0.87,
#    "AT": 1.49,
#    "BE": 0.58,
#    "CE": 0.65,
#    "CH": 0.60,
#    "CO": 0.79,
#    "DE": 0.76,
#    "EA": 0.69,
#    "ED": 1.17,
#    "EN": 1.45,
#    "ER": 2.05,
#    "ES": 1.34,
#    "HA": 0.93,
#    "HE": 3.07,
#    "HI": 0.76,
#    "IC": 0.70,
#    "IN": 2.43,
#    "IO": 0.83,
#    "IS": 1.13,
#    "IT": 1.12,
#    "LE": 0.83,
#    "LI": 0.62,
#    "LL": 0.58,
#    "MA": 0.57,
#    "ME": 0.79,
#    "ND": 1.35,
#    "NE": 0.69,
#    "NG": 0.95,
#    "NT": 1.04,
#    "OF": 1.17,
#    "OM": 0.55,
#    "ON": 1.76,
#    "OR": 1.28,
#    "OU": 0.87,
#    "RA": 0.69,
#    "RE": 1.85,
#    "RI": 0.73,
#    "RO": 0.73,
#    "SE": 0.93,
#    "SI": 0.55,
#    "ST": 1.05,
#    "TE": 1.20,
#    "TH": 3.56,
#    "TI": 1.34,
#    "TO": 1.04,
#    "UR": 0.54,
#    "VE": 0.83
#}

def strip_specials(s):
    t = s
    for c in "'.,- ?\n()\"!/:;0123456789`":
        t = t.replace(c,"")
    return t

def statistics(text):
    monograms = {}
    digrams = {}
    trigrams = {}
    for i in range(len(text)):
        monogram = strip_specials(text[i].upper())
        digram = strip_specials(text[i:i+2].upper())
        trigram = strip_specials(text[i:i+3].upper())
        if len(monogram)==1:
            if monogram not in monograms:
                monograms[monogram] = 0
            monograms[monogram] = monograms[monogram] + 1
        if len(digram)==2:
            if digram not in digrams:
                digrams[digram] = 0
            digrams[digram] = digrams[digram] + 1
        if len(trigram)==3:
            if trigram not in trigrams:
                trigrams[trigram] = 0
            trigrams[trigram] = trigrams[trigram] + 1
    return monograms,digrams,trigrams
