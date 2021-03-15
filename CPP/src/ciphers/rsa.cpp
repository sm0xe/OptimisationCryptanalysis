#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
//#include <cryptopp/osrng.h>
#include <iostream>
#include <string>
#include "../helpers/NullGenerator.h"

using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;

std::string rsa_encrypt(RSA::PublicKey publicKey, std::string plaintext){
  RSAES_PKCS1v15_Encryptor enc(publicKey);
  NullGenerator prng;
  std::string encoded, cipher;

  StringSource encrypt_rsa(plaintext, true,
      new PK_EncryptorFilter(prng, enc,
        new StringSink(cipher)
        )
      );

  StringSource encode_hex(cipher, true,
      new HexEncoder(
        new StringSink(encoded)
        )
      );
  return encoded;
}

std::string rsa_decrypt(RSA::PrivateKey privateKey, std::string encoded){
  RSAES_PKCS1v15_Decryptor dec(privateKey);
  NullGenerator prng;
  std::string ciphertext, decoded;

  StringSource decode_hex(encoded, true,
      new HexDecoder(
        new StringSink(ciphertext)
        )
      );

  StringSource decrypt_rsa(ciphertext, true,
      new PK_DecryptorFilter(prng, dec,
        new StringSink(decoded)
        )
      );
  return decoded;
}

void test_rsa(){
  //AutoSeededRandomPool prng;
  NullGenerator prng;

  InvertibleRSAFunction params;
  params.Initialize(Integer("8388651286573342341158212449924697556555614715051185220376246218323581812893174125025591897499285489354152366660216279295440660059453127926838000717445443"),17,Integer("164483358560261614532513969606366618755992445393160494517181298398501604174372369538646176110974597966241339525084523393093079855506033283659554635188993"));
  //params.GenerateRandomWithKeySize(prng,256);

  const Integer& n=params.GetModulus();
  const Integer& p=params.GetPrime1();
  const Integer& q=params.GetPrime2();
  const Integer& d=params.GetPrivateExponent();
  const Integer& e=params.GetPublicExponent();

  cout << "RSA parameters:" << endl;
  cout << "n: " << n << endl;
  cout << "p: " << p << endl;
  cout << "q: " << q << endl;
  cout << "d: " << d << endl;
  cout << "e: " << e << endl;
  cout << endl;

  RSA::PrivateKey privateKey(params);
  RSA::PublicKey publicKey(params);

  std::string plain="RSA Test", encoded, cipher, recovered;

  encoded = rsa_encrypt(publicKey, plain);

  cout << "ciphertext: " << encoded << endl;

  recovered = rsa_decrypt(privateKey, encoded);

  cout << "recovered text: " << recovered << endl;;
}
