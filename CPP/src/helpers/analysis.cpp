#include <map>
#include <string>
#include <iostream>
#include <cmath>
#include "monograms.hpp"
#include "digrams.hpp"
//#include "trigrams.hpp"
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

double chi_squared(int length, map<char,int> monograms){
  //cout << "Length: " << length << endl;
  double sum = 0.0;
  for(auto m : expected_m){
    double ei = length*m.second*0.01;
    double chi_chi = pow(monograms[m.first]-ei,2.0)/(ei);
    sum+=chi_chi*1.0;
  }
  return sum;
}

double chi_squared_playfair(int length, map<char,int> monograms){
  //cout << "Length: " << length << endl;
  double sum = 0.0;
  for(auto m : expected_m){
    if(m.first=='X') continue;
    double ei = length*m.second*0.01;
    double chi_chi = pow(monograms[m.first]-ei,2.0)/(ei);
    sum+=chi_chi*1.0;
  }
  return sum;
}

double chi_squared(int length, map<char,int> monograms, map<string,int> digrams){
  double sum = 0.0;
  for(auto d : expected_d){
    double ei = length*d.second*0.01;
    double chi_chi = pow(digrams[d.first]-ei,2)/(ei);
    sum+=chi_chi*1.0;
  }
  return sum+chi_squared(length,monograms);
}

double chi_squared_playfair(int length, map<char,int> monograms, map<string,int> digrams){
  double sum = 0.0;
  for(auto d : expected_d){
    if(d.first[0]=='X' || d.first[1]=='X') continue;
    double ei = length*d.second*0.01;
    double chi_chi = pow(digrams[d.first]-ei,2)/(ei);
    sum+=chi_chi*1.0;
  }
  return sum+chi_squared(length,monograms);
}

#ifdef TRIGRAMS_H
double chi_squared(int length, map<char,int> monograms, map<string,int> digrams, map<string,int> trigrams){
  double sum = 0.0;
  for(auto t : expected_t){
    double ei = length*t.second*0.01;
    double chi_chi = pow(trigrams[t.first]-ei,2)/(ei);
    sum+=chi_chi*1.0;
  }
  return sum+chi_squared(length,monograms,digrams);
}
#endif
