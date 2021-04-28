#include <string>
#include <iostream>

using namespace std;

string rail_fence_encode(string plaintext, int n){
  string rails[n];
  int rail=0;
  int dir=1;
  for(char i : plaintext){
    rails[rail] += i;
    if(rail==0) dir=1;
    else if(rail==n-1) dir=-1;
    rail=rail+dir;
  }
  string encoded="";
  for(int i=0; i<n; i++){
    for(char c : rails[i]){
      encoded+=c;
    }
  }
  return encoded;
}

string rail_fence_decode(string ciphertext, int n){
  int len = ciphertext.size();
  int cycle=(n-1)*2;
  string rails[n];
  int i=0;
  int rail=0;
  int count=0;
  while(i<len){
    rails[rail]+=ciphertext[i];
    i++;
    count++;
    if(rail==0){
      if(count==(len/cycle)+(len%cycle>=1)){
        count=0;
        rail=1;
      }
    }
    else if(rail<n-1){
      if(count==2*(len/cycle)+(len%cycle>rail)+(len%cycle>=cycle-rail+1)){
        count=0;
        rail++;
      }
    }
  }
  string decoded="";
  rail=0;
  int rail_i[n] = {0};
  int dir=1;
  for(int i=0; i<len; i++){
    decoded+=rails[rail][rail_i[rail]];
    rail_i[rail]++;
    if(rail==0) dir=1;
    else if(rail==n-1) dir=-1;
    rail=rail+dir;
  }
  return decoded;
}
