all: calctest condsystest condsmpltest aectablegen aecsim lookup efficiency sliqmode convtables

calctest: calctest.o CalculateFECRate.o
	g++ calctest.o CalculateFECRate.o -o calctest

condsystest: condsystest.o CalculateFECRate.o
	g++ condsystest.o CalculateFECRate.o -o condsystest

condsmpltest: condsmpltest.o CalculateFECRate.o
	g++ condsmpltest.o CalculateFECRate.o -o condsmpltest

aectablegen: aectablegen.o CalculateFECRate.o CallocND.o 
	g++ aectablegen.o CalculateFECRate.o CallocND.o \
		-o aectablegen

aecsim: aecsim.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o
	g++ aecsim.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o -o aecsim

lookup: lookup.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o
	g++ lookup.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o -o lookup

efficiency: efficiency.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o
	g++ efficiency.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o -o efficiency

sliqmode: sliqmode.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o
	g++ sliqmode.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o -o sliqmode

convtables: convtables.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o
	g++ convtables.o CalculateFECRate.o CallocND.o \
	       setupDofLookupTables.o -o convtables

calctest.o: calctest.cc CalculateFECRate.h
	g++ -c calctest.cc

condsystest.o: condsystest.cc CalculateFECRate.h
	g++ -c condsystest.cc

condsmpltest.o: condsmpltest.cc CalculateFECRate.h
	g++ -c condsmpltest.cc

aectablegen.o: aectablegen.cc CalculateFECRate.h CallocND.h
	g++ -c aectablegen.cc

aecsim.o: aecsim.cc CalculateFECRate.h CallocND.h setupDofLookupTables.h
	g++ -c aecsim.cc

lookup.o: lookup.cc CalculateFECRate.h CallocND.h setupDofLookupTables.h
	g++ -c lookup.cc

efficiency.o: efficiency.cc CalculateFECRate.h CallocND.h setupDofLookupTables.h
	g++ -c efficiency.cc

sliqmode.o: sliqmode.cc doflutparms.h sliqmode.h CalculateFECRate.h CallocND.h setupDofLookupTables.h
	g++ -c sliqmode.cc

convtables.o: convtables.cc CalculateFECRate.h CallocND.h setupDofLookupTables.h
	g++ -c convtables.cc

CallocND.o: CallocND.c CallocND.h
	g++ -c CallocND.c

setupDofLookupTables.o: setupDofLookupTables.cc setupDofLookupTables.h doflutparms.h
	g++ -c setupDofLookupTables.cc

clean:
	rm -f calctest condsystest condsmpltest \
	aectablegen aecsim lookup efficiency sliqmode \
	convtables \
	calctest.o condsystest.o \
	condsmpltest.o aectablegen.o aecsim.o lookup.o \
	efficiency.o sliqmode.o CalculateFECRate.o CallocND.o \
	setupDofLookupTables.o convtables.o

