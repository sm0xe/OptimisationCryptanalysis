#include <map>
#include <string>
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
    int first;
    int second;
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
