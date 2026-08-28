# Host-side tests for the network-graph record.
#
#   make -C rns/esp-idf/test
#   make -C rns/esp-idf/test clean
#
# No ESP-IDF and no microReticulum: netgraph.cpp's record path — compose,
# encode, parse, resolve — is arithmetic over rnsd's tables, and stubs/ supplies
# just enough platform to link it. The rnsd tables themselves are stubbed as
# data the test writes, so a record can be built for any neighbourhood without a
# board. If this build starts needing a real IDF header, something that is not
# record logic has grown into the record path.

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O1 -g -Istubs -I../include -I../src -Wno-unused-parameter

all: run

netgraph_record_test: netgraph_record_test.cpp ../src/netgraph.cpp \
                      ../include/netgraph.h ../include/rnsd.h ../src/rnsd_peers.h
	$(CXX) $(CXXFLAGS) -o $@ netgraph_record_test.cpp

run: netgraph_record_test
	./netgraph_record_test

clean:
	rm -f netgraph_record_test

.PHONY: all run clean
