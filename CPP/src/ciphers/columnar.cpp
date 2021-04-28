#include <string>
#include <iostream>
#include <map>
#include <pagmo/types.hpp>
#include <cmath>

using namespace std;

string columnar_encode(string plaintext, int col_order[], int cols){
  int rows = ceil(plaintext.size()/cols);
  char rect[rows][cols];
  string ciphertext = "";
  map<int,int> keyMap;
  for(int i=0; i<cols; i++){
    keyMap[col_order[i]]=i;
  }
  for(int i=0; i<plaintext.size(); i++){
    rect[i/cols][i%cols]=(char)plaintext[i];
  }
  for(auto i=keyMap.begin(); i!=keyMap.end(); i++){
    for(int j=0; j<rows; j++){
      ciphertext+=rect[j][i->second];
    }
  }
  return ciphertext;
}
string columnar_decode(string ciphertext, int col_order[], int cols){
  int rows = ceil(ciphertext.size()/cols);
  char rect[rows][cols];
  string plaintext = "";
  map<int,int> keyMap;
  for(int i=0; i<cols; i++){
    keyMap[col_order[i]]=i;
  }
  for(int i=0; i<cols; i++){
    for(int j=0; j<rows; j++){
      rect[j][i] = ciphertext[i*rows+j];
    }
  }
  for(int j=0; j<rows; j++){
    for(int i=0; i<cols; i++){
      plaintext+=rect[j][keyMap[i]];
    }
  }
  return plaintext;
}

string columnar_decode(string ciphertext, pagmo::vector_double dv){
  string plaintext = "";
  map<int,int> keyMap;
  int index=0;
  for(int i=0; i<dv.size(); i++){
    if(keyMap.find(int(round(dv[i])))==keyMap.end()){
      keyMap[int(round(dv[i]))]=index++;
      //std::cout << "keyMap[round("<<dv[i]<<")]="<<index-1 << endl;
    }
  }
  /*
  for(int i=0; i<dv.size(); i++){
    if(keyMap.find(i)==keyMap.end()){
      keyMap[i]=index++;
      //std::cout << "keyMap["<<i<<"]="<<index-1 << endl;
    }
  }
  */
  //std::cout << endl;
  //int cols = dv.size();
  int cols = keyMap.size();
  int rows = ceil(ciphertext.size()/cols);
  char rect[rows][cols];
  for(int i=0; i<cols; i++){
    for(int j=0; j<rows; j++){
      rect[j][i] = ciphertext[i*rows+j];
    }
  }
  for(int j=0; j<rows; j++){
    for(int i=0; i<cols; i++){
      plaintext+=rect[j][keyMap[i]];
    }
  }
  return plaintext;
}
