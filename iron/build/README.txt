                       Makefile System
                     ===================


I.  Quick-Start Guide
==============================================================================

1.  Make sure you are using bash, tcsh or csh.

2.  Set the "IRON_HOME" environment variable to your git workspace, e.g.:

        export IRON_HOME="/home/USER/IRON-current/IRON/iron"

    or

        setenv IRON_HOME /home/USER/IRON-current/IRON/iron

    where "USER" is your username.  This may be placed in your .bashrc or
    .cshrc file for convenience.  However, make sure that this file tests if
    this environment variable has already been set before setting it.  A bash
    example of this is:

        if [ -z "$IRON_HOME" ] ; then
          export IRON_HOME=/home/USER/IRON-current/IRON/iron
        fi

    A tcsh/csh example of this is:

        if (! $?IRON_HOME ) then
          setenv IRON_HOME    /home/USER/IRON-current/IRON/iron
        endif

3.  Source the appropriate setup file, e.g., for bash:

        cd /home/USER/IRON-current/IRON/iron
        . setup/debug.bash

    or for tcsh/csh:

        cd /home/USER/IRON-current/IRON/iron
        source setup/debug.csh

    Substitute the correct path and setup file name (currently debug.bash,
    optimized.bash, debug.csh, or optimized.csh) depending on your shell and
    how you would like the software built.

4.  If the UNIX platform you are using is something different than Linux with
    a 3.2 kernel, then create the needed debug and optimized style files for
    your platform in the iron/build directory using the Linux_3.2_debug and
    Linux_3.2_optimized style files as templates.  The platform name may be
    determined using the command "uname -s", and the version number (of the
    form X.Y) may be determined using the command "uname -r" and ignoring
    everything after the first and second numbers.

5.  To build all native code (C/C++) software, perform the following:

        cd /home/USER/IRON-current/IRON/iron
        make clean
        make

    Note that "make clean" and "make" may be used in any native code software
    module directory to clean or make just that module.


II.  Reference Manual
==============================================================================

The Makefile System is composed a single native code (C/C++) portion.  All
makefiles are based on GNU Make and may or may not work with other Make
programs.

To start using the Makefile System, you must first do two things in the
following order:

  o Set the "IRON_HOME" environment variable to where your IRON development
    workspace is located.  (Example:  /home/USER/IRON-current/IRON/iron).  To
    do this using bash, use:

      export IRON_HOME="/home/USER/IRON-current/IRON/iron"

    substituting the correct path in the command.  To do this using csh or
    tcsh, use:

      setenv IRON_HOME /home/USER/IRON-current/IRON/iron

    substituting the correct path in the command.  This line may be placed in
    your .bashrc or .cshrc file for convenience.  However, make sure that this
    file tests if this environment variable has already been set before
    setting it.

  o Source the appropriate setup file in iron/setup.  A setup file performs a
    number of things to make your life easier.  First, it figures out what
    platform you are on and stores this in a "BUILD_STYLE" environment
    variable.  Then, it constructs a number of environment variables
    containing the paths to different software modules.

    There are currently two different setup files, and versions of both are
    present for either bash or tcsh/csh.  The two setup files are:

      - iron/setup/debug.<shell> : This setup file is sourced if you wish to
        build native code with debugging information.  Use this setup for
        testing software components.

      - iron/setup/optimized.<shell> : This setup file is sourced if you wish
        to build native code without debugging information.  Native code will
        be built with compiler optimizations.  Use this setup for finished
        code that is ready for release.

    For example, use the following commands to source the debug setup file if
    you are using the bash shell:

      cd iron
      . setup/debug.bash

    Alternatively, use the following commands to source the debug setup file if
    you are using either the tcsh or the csh shell:

      cd iron
      source setup/debug.csh

    Note that a different setup file may be sourced at any time to change how
    the native code software is built.


1. Native Code Makefiles
------------------------

The native code makefiles are complex due to possible platform (hardware and
operating system) and compiler differences.  All platform and compiler
information is placed in a style file in iron/build.  This allows having a
single makefile for each library or executable program that includes the
appropriate style file as set in the setup file (described above).  These
style files are only created once for the platform and compiler options
required.  There are at least two different style files:

  - iron/build/Linux_3.2_debug : This style file is for building native code
    (C/C++) on any Linux 3.2.X kernel that include debugging information.

  - iron/build/Linux_3.2_optimized : This style file is for building native code
    (C/C++) on any Linux 3.2.X kernel that does not include debugging
    information.  The resulting code will be optimized.

You do not need to source these files or even look at them if you do not want
to.  However, if you are having problems with building native code, you may
need to look at the settings in these files.

There are object, library and binary directories that must be created for each
style.  All object (.o files), library (.a files) and executable files are
placed in "obj/STYLE", "lib/STYLE" and "bin/STYLE" directories within the
software module directory, where "STYLE" is the style name (currently either
Linux_3.2_debug or Linux_3.2_optimized).  This keeps the constructed files for
each style separate, allowing the same work tree to be used for building on
different platforms and with different compiler options.

Another type of file that is placed in the "obj/STYLE" directory are
dependency files (.d files).  There is one dependency file for each source
file.  These files store makefile rules based on the source file's included
header files.  Thus, if the source file "test.c" includes the header files
"common.h" and "priv.h", there will be a "obj/STYLE/test.d" file created that
informs make that "obj/STYLE/test.o" depends on the files "test.c", "common.h"
and "priv.h".  If one or both of the header files is modified, then make will
know that the object file must be remade.  Note that system include files are
not included in these dependency files, as they should not change.  All the
dependency files are created automatically before the object files are
created.

The project home directory must contain an options.mk file, containing any
project-wide compiler flags in "PROJ_FLAGS".  It may be empty.

Each native code subdirectory containing source files (.c and .cc files) must
have one or more makefiles.  At the minimum, it should have a single terminal
makefile.  If multiple terminal makefiles are required, then a single
hierarchical makefile will also be required.  The following describes the two
types of native code makefiles:

  Hierarchical Makefile:

    A template of this makefile is located in
    iron/build/makefile.hierarchical.  This makefile is used when either
    multiple directories must be built or multiple libraries and/or
    executables must be built in a single directory.

    When using a hierarchical makefile to build multiple directories, copy the
    makefile template iron/build/makefile.hierarchical to the appropriate
    directory as "makefile" and fill in the "SRC_DIRS" variable.  Note that
    the paths specified in this variable must be relative to the directory the
    makefile is in.  Do not specify absolute paths, as they will not work.
    There is a hierarchical makefile in "iron" that will build the entire
    native code system.  When adding a new software module to the system, add
    the path to the software to this hierarchical makefile, keeping in mind
    that the order that modules are built is important due to library
    dependencies.

    When using a hierarchical makefile to build multiple libraries and/or
    executables in a single directory, copy the makefile template
    iron/build/makefile.hierarchical to the appropriate directory as
    "makefile" and fill in the "ADJACENT_MAKEFILES" variable.  Each makefile
    specified in this variable must be a terminal makefile (explained below)
    and must be located in the directory.  Since the names of the terminal
    makefiles must be different than "makefile", add an extension to
    "makefile" that describes the library or executable being built
    (e.g. makefile.test_app).

  Terminal Makefile:

    This makefile is located in each native source code directory where a
    library or executable must be built.  If only a single library or
    executable is being built in the directory, copy the makefile template
    iron/build/makefile.terminal as "makefile" in the native code directory.
    If more than one library and/or executable is being built in the
    directory, use a hierarchical makefile (described above) called "makefile"
    and copy the makefile template iron/build/makefile.terminal as one or more
    "makefile.xxxx" makefiles, where each "xxxx" is a descriptive name of the
    library or executable being built by the makefile.

    If the terminal makefile is being used to build a library, then fill in
    the "INCLUDE_PATH", "OPT_FLAGS", "LIB_NAME" and "LIB_SOURCE" variables.
    See the examples in the terminal makefile template for the exact format of
    this information.  Remember to use "\" symbols at the and of a line to
    continue to the next line.

    If the terminal makefile is being used to build an executable, then fill
    in the "INCLUDE_PATH", "OPT_FLAGS", "EXE_NAME", "EXE_SOURCE", "EXE_LIBS"
    and "LIBRARY_PATH" variables.  See the examples in the terminal makefile
    template for the exact format of this information.  Remember to use "\"
    symbols at the and of a line to continue to the next line.

The native makefile system also supports library dependencies.  In other
words, if you have a makefile to build an executable called "test" and this
executable uses the "libcommon.a" library, if you make "libcommon.a", make
"test", remake "libcommon.a" with some changes, then attempt to make "test",
"test" will be remade.

How to:

  Clean all native code (removes all dependency, object, library, and binary
  files):
    cd iron
    make clean

  Make all native code:
    cd iron
    make

  Clean a native code module:
    cd iron/<moduleName>/src
    make clean

  Make a native code module:
    cd iron/<moduleName>/src
    make
