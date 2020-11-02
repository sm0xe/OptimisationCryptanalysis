FILES := $(patsubst %.cpp,bin/%,$(wildcard *.cpp))
all: $(FILES)
bin/%: %.cpp
	g++ -pthread -lpagmo -lboost_serialization -ltbb -std=c++17 -O2 -o $@ $<
