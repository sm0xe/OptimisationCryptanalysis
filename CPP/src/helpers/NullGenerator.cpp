#include <cryptopp/osrng.h>
#include "NullGenerator.h"
using namespace CryptoPP;

byte NullGenerator::GenerateByte(){
  return (byte) 0;
}
unsigned int NullGenerator::GenerateBit(){
  return 0;
}
CryptoPP::word32 NullGenerator::GenerateWord32(){
  return 0;
}
void NullGenerator::GenerateBlock(byte *output, std::size_t length){
  memset(output, 0x00, length);
}
void NullGenerator::IncorporateEntropy(byte *input, std::size_t length){}
