#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;


std::string des_encrypt(std::array<std::byte,DES::DEFAULT_KEYLENGTH> keyarray, std::string plaintext){
  SecByteBlock key((const byte*)keyarray.data(),DES::DEFAULT_KEYLENGTH);

  std::string encoded, cipher;

  try{
    ECB_Mode<DES>::Encryption e;
    e.SetKey(key, key.size());

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
    ECB_Mode<DES>::Decryption d;
    d.SetKey(key, key.size());
    StringSource decode_hex(encoded, true,
        new HexDecoder(
          new StringSink(ciphertext)
          )
        );
    StringSource decrypt_des(ciphertext, true,
        new StreamTransformationFilter(d,
          new StringSink(recovered)
          )
        );
    return recovered;
  }
  catch(const CryptoPP::Exception& d){
    cerr << d.what() << endl;
    exit(1);
  }
}

void test_des(std::array<std::byte,DES::DEFAULT_KEYLENGTH> keyarray){

  std::string plain = "ECB Mode Test";

  std::string encoded = des_encrypt(keyarray, plain);
  cout << "ciphertext: " << encoded << endl;

  std::string recovered = des_decrypt(keyarray, encoded);
  cout << "recoveredtext: " << recovered<< endl;
}
