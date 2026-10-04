CXX = g++

CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -I.

TARGETS = prover verifier

all: $(TARGETS)

prover: prover.cpp zkp_core.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

verifier: verifier.cpp zkp_core.hpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.txt

.PHONY: all clean
