This directory contains code for generating and testing the lookup parameter
tables used within SLIQ to construct the mid-game and end-game DOF lookup
tables for the GNAT Adaptive Error Control (AEC) algorithm

aectablegen.cc
	Computes the DOF midgame and endgame lookup table generation
        parameters. The output is to stdout: we typically redirect the
	output to doflutparms.h

doflutparms.h
	Captured output from running aectablegen > doflutparms.h

efficiency.cc
	Computes the efficiency values or the efficiency lookup table
	data. Modify the PRINT_HEADER_FILE constant to switch between the
	two output formats. The output is to stdout.

sliqmode.cc
	Computes the FEC mode and efficiency value that the SLIQ protocol
	would use for a given PER, TgtPrecv, TgtLat, MaxRTT, MaxOWD (maximum
	local-to-remote one-way delay), and MaxPST (maximum packet
	serialization time).

aecsim.cc
	Simulates sending packets over a channel with a fixed Bernoulli
	packet loss rate and calculates both the Precv and efficiency
	for at a given operating point (packet loss rate, allowed number
	of rounds, target Precv, and number of source packets).
	Has doflutparms.h as a #include

aeccarqresults.txt
	Captured output from running aecsim > aeccarqresults.txt

setupDofLookupTables.cc,.h
        Contains the method for converting a DOF LUT Parameter into a
	pair of DOF lookup tables (mid game and end game tables) for a
	target operating point

CalculateFECRate.cc,.h
	Contains methods for calculating various probabilities of success
	for simple fec, systematic coded fec, conditonal simple fec,
	conditional systematic fec, etc

calctest      
condsmpltest
condsystest
	Test routines for checking different methods in CalculateFECRate

lookup
	Computes various theoretical values for using aec at a given
	operating point (packet loss rate, allowed number
	of rounds, target Precv, and number of source packets).

convtables.cc
	Experimental code that pre-converts the DOF LUT parms into a
	set of midgame and endgame lookup tables to avoid constructing
	these two tables on-the-fly at run time

CallocND.c,.h
	Handy allocators for mult-dimensional arrays
