#include <cryptopp/osrng.h>
#pragma once
class NullGenerator : public CryptoPP::RandomNumberGenerator{
  public:
    virtual CryptoPP::byte GenerateByte();
    virtual unsigned int GenerateBit();
    virtual CryptoPP::word32 GenerateWord32();
    virtual void GenerateBlock(CryptoPP::byte *output, size_t length);
    virtual void IncorporateEntropy(CryptoPP::byte *input, size_t length);
};
