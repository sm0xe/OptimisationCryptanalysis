#include <map>
#include <string>
#include <iostream>
#include <cmath>
#include "monograms.hpp"
#include "digrams.hpp"
#include "trigrams.hpp"

#define UNIGRAM_WEIGHT 0.1
#define DIGRAM_WEIGHT 0.1
#define TRIGRAM_WEIGHT 0.8

using namespace std;
map<char,int> get_monogram_frequencies(string ciphertext){
  int freqs[26] = {0};
  map<char,int> monogram_frequency;
  for(int i=0; i<ciphertext.length(); i++){
    if(ciphertext[i] >= 'A' && ciphertext[i] <= 'Z'){
      freqs[ciphertext[i]-'A']++;
    }
    if(ciphertext[i] >= 'a' && ciphertext[i] <= 'z'){
      freqs[ciphertext[i]-'a']++;
    }
  }
  for(int i=0; i<26; i++){
    monogram_frequency[(char)i+'A']=freqs[i];
  }
  return monogram_frequency;
}

map<string,int> get_digram_frequencies(string ciphertext){
  int freqs[26][26] = {{0}};
  map<string,int> digram_frequency;
  for(int i=0; i<ciphertext.length(); i++){
    int first=-1;
    int second=-1;
    if(ciphertext[i] >= 'A' && ciphertext[i] <= 'Z'){
      first = ciphertext[i]-'A';
    }
    if(ciphertext[i] >= 'a' && ciphertext[i] <= 'z'){
      first = ciphertext[i]-'a';
    }
    if(ciphertext[i+1] >= 'A' && ciphertext[i+1] <= 'Z'){
      second = ciphertext[i+1]-'A';
    }
    if(ciphertext[i+1] >= 'a' && ciphertext[i+1] <= 'z'){
      second = ciphertext[i+1]-'a';
    }
    if(first==-1 || second==-1) continue;
    freqs[first][second]++;
  }
  for(int i=0; i<26; i++){
    for(int j=0; j<26; j++){
      string digram({(char)(i+'A'),(char)(j+'A')});
      digram_frequency[digram]=freqs[i][j];
    }
  }
  return digram_frequency;
}

map<string,int> get_trigram_frequencies(string ciphertext){
  int freqs[26][26][26] = {{{0}}};
  map<string,int> trigram_frequency;
  for(int i=0; i<ciphertext.length(); i++){
    int first=-1;
    int second=-1;
    int third=-1;
    if(ciphertext[i] >= 'A' && ciphertext[i] <= 'Z'){
      first = ciphertext[i]-'A';
    }
    if(ciphertext[i] >= 'a' && ciphertext[i] <= 'z'){
      first = ciphertext[i]-'a';
    }
    if(ciphertext[i+1] >= 'A' && ciphertext[i+1] <= 'Z'){
      second = ciphertext[i+1]-'A';
    }
    if(ciphertext[i+1] >= 'a' && ciphertext[i+1] <= 'z'){
      second = ciphertext[i+1]-'a';
    }
    if(ciphertext[i+2] >= 'A' && ciphertext[i+2] <= 'Z'){
      third = ciphertext[i+2]-'A';
    }
    if(ciphertext[i+2] >= 'a' && ciphertext[i+2] <= 'z'){
      third = ciphertext[i+2]-'a';
    }
    if(first==-1 || second==-1 || third==-1) continue;
    freqs[first][second][third]++;
  }
  for(int i=0; i<26; i++){
    for(int j=0; j<26; j++){
      for(int k=0; k<26; k++){
        string trigram({(char)(i+'A'),(char)(j+'A'),(char)(k+'A')});
        trigram_frequency[trigram]=freqs[i][j][k];
      }
    }
  }
  return trigram_frequency;
}

double van_vuuren(long int n, std::map<char,int> monograms){
  double sum=0;
  double p_min = 1e10;
  for(int i=0; i<26; i++){
    double expected = (double)n*expected_m[i]*0.01;
    if(p_min>expected) p_min=expected;
    sum+=abs(expected-monograms[i]);
  }
  return (2*((double)n-p_min)-sum)/(2*((double)n-p_min));
}

double chi_squared(int length, map<char,int> monograms){
  //cout << "Length: " << length << endl;
  double sum = 0.0;
  for(int i=0; i<26; i++){
    double ei = (double)length*expected_m[i]*0.01;
    double chi_chi = pow(monograms[i]-ei,2.0)/(ei);
    sum+=(chi_chi*UNIGRAM_WEIGHT);
  }
  return sum;
}

double chi_squared_playfair(int length, map<char,int> monograms){
  double sum = 0.0;
  for(int i=0; i<26; i++){
    if(i+'A'=='X') continue;
    double ei = (double)length*expected_m[i]*0.01;
    double chi_chi = pow(monograms[i]-ei,2.0)/(ei);
    sum+=chi_chi*UNIGRAM_WEIGHT;
  }
  return sum;
}

double chi_squared(int length, map<char,int> monograms, map<string,int> digrams){
  double sum = 0.0;
  for(int i=0; i<26; i++){
    for(int j=0; j<26; j++){
      string d = {(char)(i+'A'),(char)(j+'A')};
      double ei = (double)length*expected_d[i][j]*0.01;
      double chi_chi;
      if(ei==0 || digrams.find(d)==digrams.end()){
        continue;
      }
      else{
        chi_chi = pow(digrams[d]-ei,2.0)/(ei);
      }
      sum+=(chi_chi*DIGRAM_WEIGHT);
    }
  }
  return sum+chi_squared(length,monograms);
}

double chi_squared_playfair(int length, map<char,int> monograms, map<string,int> digrams){
  double sum = 0.0;
  for(int i=0; i<26; i++){
    if('A'+i=='X') continue;
    for(int j=0; j<26; j++){
      if('A'+j=='X') continue;
      string d = {(char)(i+'A'),(char)(j+'A')};
      double ei = (double)length*expected_d[i][j]*0.01;
      double chi_chi;
      if(ei==0 || digrams.find(d)==digrams.end()){
        continue;
      }
      else{
        chi_chi = pow(digrams[d]-ei,2.0)/(ei);
      }
      sum+=chi_chi*DIGRAM_WEIGHT;
    }
  }
  return sum+chi_squared_playfair(length,monograms);
}

#ifdef TRIGRAMS_H
double chi_squared_playfair(int length, map<char,int> monograms, map<string,int> digrams, map<string,int> trigrams){
  double sum = 0.0;
  for(int i=0; i<26; i++){
    if(i+'A'=='X') continue;
    for(int j=0; j<26; j++){
      if(j+'A'=='X') continue;
      for(int k=0; k<26; k++){
        if(k+'A'=='X') continue;
        string t = {(char)(i+'A'),(char)(j+'A'),(char)(k+'A')};
        double ei = (double)length*expected_t[i][j][k]*0.01;
        double chi_chi;
        if(ei==0 || trigrams.find(t)==trigrams.end()){
          continue;
        }
        else{
          chi_chi = pow(trigrams[t]-ei,2.0)/(ei);
        }
        sum+=chi_chi*TRIGRAM_WEIGHT;
      }
    }
  }
  return sum+chi_squared_playfair(length,monograms,digrams);
}

double chi_squared(int length, map<char,int> monograms, map<string,int> digrams, map<string,int> trigrams){
  double sum = 0.0;
  for(int i=0; i<26; i++){
    for(int j=0; j<26; j++){
      for(int k=0; k<26; k++){
        string t = {(char)(i+'A'),(char)(j+'A'),(char)(k+'A')};
        double ei = (double)length*expected_t[i][j][k]*0.01;
        double chi_chi;
        if(ei==0 || trigrams.find(t)==trigrams.end()){
          continue;
        }
        else{
          chi_chi = pow(trigrams[t]-ei,2.0)/(ei);
        }
        sum+=(chi_chi*TRIGRAM_WEIGHT);
      }
    }
  }
  return sum+chi_squared(length,monograms,digrams);
}
#endif

double index_of_coincidence(int n, map<char,int> monograms){
  double sum=0;
  for(auto i : monograms){
    sum+=i.second*(i.second-1);
  }
  return abs(sum*10000/(n*(n-1))-686);
}
int find_vigenere_key_length(string ciphertext){
  int best_key_l = 0;
  double best_key_f = 1e25;
  for(int i=1; i<=10; i++){
    double fitness_sum=0;
    for(int j=0; j<i; j++){
      string cipherchunk = "";
      int size=0;
      for(int k=j; k<ciphertext.length(); k+=i){
        cipherchunk+=ciphertext[k];
        size++;
      }
      //fitness_sum+=chi_squared(size,get_monogram_frequencies(cipherchunk));
      fitness_sum+=index_of_coincidence(size,get_monogram_frequencies(cipherchunk));
    }
    if(fitness_sum/i < best_key_f){
      best_key_f = fitness_sum/i;
      best_key_l = i;
    }
    //cout << "DEBUG: key length " << i << " has fitness " << fitness_sum/i << endl;
  }
  return best_key_l;
}
