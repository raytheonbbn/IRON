Overviews, dicussions, and patches:

A description of gulp and its use as a replacement for tcpdump to obtain
gigabit rate lossless packet capture by the author can be found here.

corey.elsewhere.org/gulp

The source code for the base gulp implementation code can be found here.

corey.elsewhere.org/gulp/gulp.tgz

The discussion thread on patching gulp for 64 bit architectures
can be found here.

http://blog.crox.net/archives/72-gulp-tcpdump-alternative-for-lossless-capture-on-linux.html

The two patches referenced in the above article can be found here and here

http://blog.crox.net/01-gulp-amd64.patch.gz
http://blog.crox.net/02-gulp-ntGFZ.patch.gz

=============

Building the 64 bit version

Can be done by running the build script build.sh

This will untar the gulp distribution, uncompress and apply the two
patch files, and then run make.

I've tested this on a 64 bit laptop running Ubuntu 14.04, including
capturing packets from a wireless interface and then viewing the
capture file in wireshark -- everything checks out fine.
