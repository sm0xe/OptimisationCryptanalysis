#include <iostream>
#include <string>
#include <cmath>
#include <pagmo/types.hpp>

using namespace std;

string vigenere_encrypt(string plaintext, string key){
  string ciphertext(plaintext);
  int key_counter = 0;
  int key_length = key.length();
  for(int i=0; i<plaintext.length(); i++){
    if(plaintext[i]>='A' && plaintext[i]<='Z'){
      ciphertext[i] = (char) (plaintext[i]+key[key_counter]-2*'A')%26+'A';
      key_counter = (key_counter+1) % key_length;
    }
    else if(plaintext[i]>='a' && plaintext[i]<='z'){
      ciphertext[i] = (char) (plaintext[i]+key[key_counter]-'A'-'a')%26+'a';
      key_counter = (key_counter+1) % key_length;
    }
  }
  return ciphertext;
}

string vigenere_decrypt(string ciphertext, string key){
  string plaintext(ciphertext);
  int key_counter = 0;
  int key_length = key.length();
  for(int i=0; i<ciphertext.length(); i++){
    if(ciphertext[i]>='A' && ciphertext[i]<='Z'){
      plaintext[i] = (char) (26+ciphertext[i]-key[key_counter])%26+'A';
      key_counter = (key_counter+1) % key_length;
    }
    else if(ciphertext[i]>='a' && ciphertext[i]<='z'){
      plaintext[i] = (char) (26+ciphertext[i]-key[key_counter]+'A'-'a')%26+'a';
      key_counter = (key_counter+1) % key_length;
    }
  }
  return plaintext;
}

string vigenere_decrypt(string ciphertext, const pagmo::vector_double &key, int length){
  string plaintext(ciphertext);
  int key_counter = 0;
  int key_length = length;
  for(int i=0; i<ciphertext.length(); i++){
    if(ciphertext[i]>='A' && ciphertext[i]<='Z'){
      plaintext[i] = (char) (26+ciphertext[i]-round(key[key_counter])-'A')%26+'A';
      key_counter = (key_counter+1) % key_length;
    }
    else if(ciphertext[i]>='a' && ciphertext[i]<='z'){
      plaintext[i] = (char) (26+ciphertext[i]-round(key[key_counter])+'A'-'a')%26+'a';
      key_counter = (key_counter+1) % key_length;
    }
  }
  return plaintext;
}

bool test_vigenere(){
  string plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ'abcdefghijklmnopqrstuvwxyz";
  string key = "KEY";
  string ciphertext = vigenere_encrypt(plaintext,key);
  string decrypted_ciphertext = vigenere_decrypt(ciphertext,key);
  return(ciphertext=="KFANIDQLGTOJWRMZUPCXSFAVID'ylgbojermhupkxsnavqdytgbwj" && plaintext==decrypted_ciphertext);
}
