#include <iostream>
#include <cmath>
#include <string>
#include <set>
#include <pagmo/types.hpp>

using namespace std;

struct playfair_table {
  char table[5][5];
};

struct playfair_table generate_playfair_table(string key){
  set<char> used_characters;
  used_characters.insert('J');
  int row=0;
  int col=0;
  struct playfair_table pf;

  for(int i=0; i<key.length(); i++){
    if(!used_characters.contains(key[i])){
      pf.table[row][col] = key[i];
      used_characters.insert(key[i]);
      col++;
      if(col==5){
        col=0;
        row++;
      }
    }
  }
  for(char i='A'; i<='Z'; i++){
    if(!used_characters.contains(i)){
      pf.table[row][col] = i;
      used_characters.insert(i);
      col++;
      if(col==5){
        col=0;
        row++;
      }
    }
  }
  return(pf);
}

string playfair_encrypt(string plaintext, string key){
  
  string ciphertext;
  for(int i=0; i<plaintext.length();i+=2){
    char first = plaintext[i];
    char second = plaintext[i+1];
    if(first==second){
      second='X';
      i--;
    }
    size_t where_first = key.find_first_of(first);
    size_t where_second = key.find_first_of(second);
    int first_row = where_first/5;
    int first_col = where_first%5;
    int second_row = where_second/5;
    int second_col = where_second%5;

    if(first_row == second_row){
      ciphertext.push_back((char) key[first_row*5+(first_col+1)%5]);
      ciphertext.push_back((char) key[first_row*5+(second_col+1)%5]);
    }
    else if(first_col == second_col){
      ciphertext.push_back((char) key[((first_row+1)%5)*5+first_col]);
      ciphertext.push_back((char) key[((second_row+1)%5)*5+first_col]);
    }
    else{
      ciphertext.push_back((char) key[first_row*5+second_col]);
      ciphertext.push_back((char) key[second_row*5+first_col]);
    }
  }
  return(ciphertext);
}

string playfair_decrypt(string ciphertext, string key){
  string plaintext;
  for(int i=0; i<ciphertext.length();i+=2){
    char first = ciphertext[i];
    char second = ciphertext[i+1];
    size_t where_first = key.find_first_of(first);
    size_t where_second = key.find_first_of(second);
    int first_row = where_first/5;
    int first_col = where_first%5;
    int second_row = where_second/5;
    int second_col = where_second%5;

    if(first_row == second_row){
      plaintext.push_back((char) key[first_row*5+(first_col+4)%5]);
      plaintext.push_back((char) key[first_row*5+(second_col+4)%5]);
    }
    else if(first_col == second_col){
      plaintext.push_back((char) key[((first_row+4)%5)*5+first_col]);
      plaintext.push_back((char) key[((second_row+4)%5)*5+first_col]);
    }
    else{
      plaintext.push_back((char) key[first_row*5+second_col]);
      plaintext.push_back((char) key[second_row*5+first_col]);
    }
  }
  return(plaintext);
}
string dv_to_pf_key(const pagmo::vector_double &dv){
  set<char> used;
  used.insert('J');
  int count=0;
  string key="";
  for(auto i : dv){
    char c = (char)round(i) + 'A';
    if(used.find(c)==used.end()){
      key+=c;
      used.insert(c);
    }
    else{
      for(;count<26;count++){
        char c = (char)count + 'A';
        if(used.find(c)==used.end()){
          key+=c;
          used.insert(c);
        }
      }
    }
  }
  while(count<26){
    char c = (char)count + 'A';
    if(used.find(c)==used.end()){
      key+=c;
      used.insert(c);
    }
    count++;
  }
  return key;
}

string playfair_decrypt(string ciphertext, const pagmo::vector_double &dv){
  string key = dv_to_pf_key(dv);
  return playfair_decrypt(ciphertext, key);
}

bool test_playfair(){
  string plaintext = "THISISATESTSTRINGSOON";
  string key = "PLAYFIREXMBCDGHKNOQSTUVWZ";
  string ciphertext = playfair_encrypt(plaintext,key);
  string decrypted_ciphertext = playfair_decrypt(ciphertext,key);
  return(ciphertext=="ZBMKMKPVMOZKUIRKHQQEQO" && decrypted_ciphertext=="THISISATESTSTRINGSOXON");
}
