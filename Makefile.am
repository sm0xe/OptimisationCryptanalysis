AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
bin_PROGRAMS = cryptanalysis

AM_CXXFLAGS = -pthread -lpagmo -lboost_serialization -ltbb -lcryptopp -std=c++20 -O2 

cryptanalysis_SOURCES = CPP/src/cryptanalysis.cpp CPP/src/helpers/analysis.cpp CPP/src/helpers/NullGenerator.cpp CPP/src/helpers/hexifier.cpp CPP/src/ciphers/substitution.cpp CPP/src/ciphers/vigenere.cpp CPP/src/ciphers/playfair.cpp CPP/src/ciphers/des.cpp CPP/src/ciphers/aes.cpp CPP/src/ciphers/rsa.cpp CPP/src/ciphers/speck.cpp
