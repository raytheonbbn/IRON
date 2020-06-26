# The NORM libraries are built with waf. The executable shell script,
# build.sh, builds the NORM distribution and the executable shell
# script, clean.sh, clean up the distribution.
#
# This makefile does not conform to the normal GNAT makefiles. Instead
# it simply calls build.sh for the 'segment' target to ensure that the
# NORM libraries are built as needed. Note that the built libraries
# are placed in the build/ subdirectory in the norm-1.5.8/
# directory. Any GNAT code needing the link in the NORM libraries,
# currently only nftp has this requirement, need to reference the
# appropriate location for the NORM libraries.
#
# clean.sh is called for the 'clean' target.
#
# While not the standard format GNAT makefile, we can still refer to
# this makefile in the top-level GNAT hierarchical makefile when
# building the GNAT system.

segment:
	./build.sh

clean:
	./clean.sh
