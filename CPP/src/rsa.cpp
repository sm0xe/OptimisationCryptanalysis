#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <string>

using namespace CryptoPP;
using std::cout;
using std::cerr;
using std::endl;

void test_rsa(){
  AutoSeededRandomPool prng;

  InvertibleRSAFunction params;
  params.Initialize(Integer("8388651286573342341158212449924697556555614715051185220376246218323581812893174125025591897499285489354152366660216279295440660059453127926838000717445443"),17,Integer("164483358560261614532513969606366618755992445393160494517181298398501604174372369538646176110974597966241339525084523393093079855506033283659554635188993"));
  //params.GenerateRandomWithKeySize(prng,512);

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

  RSAES_OAEP_SHA_Encryptor enc(publicKey);

  StringSource encrypt_rsa(plain, true,
      new PK_EncryptorFilter(prng, enc,
        new StringSink(cipher)
        )
      );

  StringSource encode_hex(cipher, true,
      new HexEncoder(
        new StringSink(encoded)
        )
      );

  cout << "ciphertext: " << encoded << endl;

  RSAES_OAEP_SHA_Decryptor dec(privateKey);

  StringSource decrypt_rsa(cipher, true,
      new PK_DecryptorFilter(prng, dec,
        new StringSink(recovered)
        )
      );

  cout << "recovered text: " << recovered;

}
