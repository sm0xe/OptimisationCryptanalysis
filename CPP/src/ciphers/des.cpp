#include <iostream>
#include <string>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <pagmo/types.hpp>

using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;


std::string des_encrypt(std::array<std::byte,DES::DEFAULT_KEYLENGTH> keyarray, std::string plaintext){
  SecByteBlock key((const byte*)keyarray.data(),DES::DEFAULT_KEYLENGTH);

  std::string encoded, cipher;

  try{
    ECB_Mode<DES>::Encryption e(key, key.size());

    StringSource encrypt_des(plaintext, true,
        new StreamTransformationFilter(e,
          new StringSink(cipher)
          )
        );
  }
  catch(const CryptoPP::Exception& e){
    cerr << e.what() << endl;
    exit(1);
  }

  StringSource encode_hex(cipher, true,
      new HexEncoder(
        new StringSink(encoded)
        )
      );

  return encoded;
}

std::string des_decrypt(std::array<std::byte,DES::DEFAULT_KEYLENGTH> keyarray, std::string encoded){
  SecByteBlock key((const byte*)keyarray.data(),DES::DEFAULT_KEYLENGTH);

  std::string ciphertext, recovered;

  try{
    ECB_Mode<DES>::Decryption d(key, key.size());
    StringSource decode_hex(encoded, true,
        new HexDecoder(
          new StringSink(ciphertext)
          )
        );
    StringSource decrypt_des(ciphertext, true,
        new StreamTransformationFilter(d,
          new StringSink(recovered),
          BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING
          )
        );
    return recovered;
  }
  catch(const CryptoPP::Exception& d){
    cerr << d.what() << endl;
    exit(1);
  }
}

std::string des_decrypt(const pagmo::vector_double &dv,std::string encoded){
  std::array<std::byte,DES::DEFAULT_KEYLENGTH> key;
  for(int i=0; i<dv.size(); i++){
    key[i]=(std::byte) dv[i];
  }
  return des_decrypt(key,encoded);
}

void test_des(std::array<std::byte,DES::DEFAULT_KEYLENGTH> keyarray){

  std::string plain = "ECB Mode Test";

  std::string encoded = des_encrypt(keyarray, plain);
  cout << "ciphertext: " << encoded << endl;

  std::string recovered = des_decrypt(keyarray, encoded);
  cout << "recovered text: " << recovered<< endl;
}
