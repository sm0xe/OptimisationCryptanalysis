#include <string>
#include <iostream>
#include <pagmo/types.hpp>
#include <set>

using namespace std;

string substitute(string orig, string key){
  string substituted(orig);
  for(int i=0; i<substituted.length(); i++){
    if(orig[i]>='A' && orig[i]<='Z'){
      substituted[i] = key[orig[i]-'A'];
    }
    else if (orig[i]>='a' && orig[i]<='z'){
      substituted[i] = (char) key[orig[i]-'a']+32;
    }
    else{
      substituted[i] = orig[i];
    }
  }
  return substituted;
}

string dv_to_msub_key(const pagmo::vector_double &dv){
  set<char> used;
  int count=0;
  string key="";
  for(auto i : dv){
    char c = (char)i+'A';
    if(used.find(c)==used.end()){
      key+=c;
      used.insert(c);
    }
    else{
      for(;count<26;count++){
        char c = (char)count+'A';
        if(used.find(c)==used.end()){
          key+=c;
          used.insert(c);
        }
      }
    }
  }
  return key;
}

string substitute(string orig, const pagmo::vector_double &dv){
  string key = dv_to_msub_key(dv);
  return substitute(orig,key);
}

bool test_substitutions(){
  string original_string("ABCDEFGHIJKLMNOPQRSTUVWXYZ'abcdefghijklmnopqrstuvwxyz");
  string substitute_key("XYZABCDEFGHIJKLMNOPQRSTUVW");
  string substituted_string = substitute(original_string,substitute_key);
  return(substituted_string=="XYZABCDEFGHIJKLMNOPQRSTUVW'xyzabcdefghijklmnopqrstuvw");
}
