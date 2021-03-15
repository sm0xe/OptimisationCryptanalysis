#include <string>
#include <iostream>
#include "../helpers/NullGenerator.h"
#include <cryptopp/speck.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <pagmo/types.hpp>

using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

string speck_encrypt(std::array<std::byte,SPECK64::DEFAULT_KEYLENGTH> keyarray, string plaintext){
  NullGenerator prng;
  SecByteBlock key((const byte*)keyarray.data(),SPECK64::DEFAULT_KEYLENGTH);
  string cipher, encoded;

  try{
    ECB_Mode<SPECK64>::Encryption e(key, key.size());
    StringSource encrypt_speck(plaintext, true,
        new StreamTransformationFilter(e,
          new StringSink(cipher)
          )
        );
    StringSource encode_hex(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
  }
  catch(const CryptoPP::Exception& e){
    cerr << e.what() << endl;
    exit(1);
  }


}

string speck_decrypt(std::array<std::byte,SPECK64::DEFAULT_KEYLENGTH> keyarray, string encoded){
  NullGenerator prng;
  SecByteBlock key((const byte*)keyarray.data(),SPECK64::DEFAULT_KEYLENGTH);

  string ciphertext, recovered;


  try{
    ECB_Mode<SPECK64>::Decryption d(key, key.size());
    StringSource decode_hex(encoded, true,
        new HexDecoder(
          new StringSink(ciphertext)
          )
        );
    StringSource s(ciphertext, true,
        new StreamTransformationFilter(d,
          new StringSink(recovered)
          )
        );
    return recovered;
  }
  catch(const CryptoPP::Exception& e){
    return ciphertext;
    //cerr << e.what() << endl;
    //exit(1);
  }
}

string speck_decrypt(const pagmo::vector_double &dv, string encoded){
  std::array<std::byte,SPECK64::DEFAULT_KEYLENGTH> key;
  for(int i=0; i<dv.size(); i++){
    key[i] = (std::byte) dv[i];
  }
  return speck_decrypt(key,encoded);
}

void test_speck(std::array<std::byte,SPECK64::DEFAULT_KEYLENGTH> keyarray){
  /*
  SecByteBlock key((const byte*)keyarray.data(),SPECK64::DEFAULT_KEYLENGTH);
  cout << "Key: ";
  StringSource kss(key, key.size(), true, new HexEncoder(new FileSink(cout)));
  cout << endl;
  */

  string plain = "ECB Mode Test";
  string encoded = speck_encrypt(keyarray,plain);

  cout << "Cipher text: " << encoded << endl;

  string recovered = speck_decrypt(keyarray,encoded);

  cout << "Recovered text: " << recovered << endl;

}

