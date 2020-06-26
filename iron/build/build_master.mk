#=============================================================================
# build_master.mk
#
# Purpose:  This file is to be included by terminal.mk.
#=============================================================================

#-----------------------------------------------------------------------------
# The following table of SYMBOLS identifies those needed by this component of
# the build machinery.
#
# SYMBOL             DEFINED IN    DESCRIPTION
# ------------------ ------------- -------------------------------------------
# SO_NAME            <terminal>    Base name for the shared object.
# SO_MAJ_NUM         <terminal>    Major number for the shared object.
# SO_MIN_NUM         <terminal>    Minor number for the shared object.
# SO_REV_NUM         <terminal>    Revision number for the shared object.
# LIB_NAME           <terminal>    Base name for the library.
# EXE_NAME           <terminal>    Name for the executable.
# SO_SOURCE          <terminal>    C/C++ source files in the shared object.
# LIB_SOURCE         <terminal>    C/C++ source files in the library.
# EXE_SOURCE         <terminal>    C/C++ source file for the executable.
#
# SO_LOCATION        <style file>  Location for the shared object files.
# OBJ_LOCATION       <style file>  Location for the object files.
# LIB_LOCATION       <style file>  Location for the library files.
# EXE_LOCATION       <style file>  Location for the executable files.
# TESTR_LOCATION     <style file>  Location for the tests results files.
#
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
# Makefile definitions.
#-----------------------------------------------------------------------------

.PRECIOUS: ${LIB_LOCATION}/${LIB_NAME}
.SUFFIXES: .so .a .o .c .cc .cpp .h .hh .hpp

#-----------------------------------------------------------------------------
# Directory search directives.  Create a "vpath" for finding libraries that
# shared objects and executables depend on.
#-----------------------------------------------------------------------------

EXE_LIBS_PATH_1 := ${patsubst -L%,%,${EXE_LIBRARY_PATH}}
EXE_LIBS_PATH   := ${strip ${EXE_LIBS_PATH_1}}

SO_LIBS_PATH_1 := ${patsubst -L%,%,${SO_LIBRARY_PATH}}
SO_LIBS_PATH   := ${strip ${SO_LIBS_PATH_1}}

vpath %.a ${EXE_LIBS_PATH} ${SO_LIBS_PATH}
vpath %.so ${EXE_LIBS_PATH} ${SO_LIBS_PATH}

#-----------------------------------------------------------------------------
# Macro definitions.  Use the macros to determine if the exectuable requires
# using the C or C++ compiler.
#-----------------------------------------------------------------------------

FIND_FILE_TYPES = \
	echo "null"; \
	for i in . $$files; \
	do \
	  echo `echo $$i|sed -n "/\.$$suffix$$/p"`; \
	done; \
	echo

EXE_CC_MACRO = \
	suffix=cc; \
	files=`echo ${EXE_SOURCE}`; \
	${FIND_FILE_TYPES}

EXE_CPP_MACRO = \
	suffix=cpp; \
	files=`echo ${EXE_SOURCE}`; \
	${FIND_FILE_TYPES}

EXE_CC_SOURCE_NULL := ${shell ${EXE_CC_MACRO}} ${shell ${EXE_CPP_MACRO}}
EXE_CC_SOURCE      := ${strip ${EXE_CC_SOURCE_NULL:null=}}

SO_CC_MACRO = \
	suffix=cc; \
	files=`echo ${SO_SOURCE}`; \
	${FIND_FILE_TYPES}

SO_CPP_MACRO = \
	suffix=cpp; \
	files=`echo ${SO_SOURCE}`; \
	${FIND_FILE_TYPES}

SO_CC_SOURCE_NULL := ${shell ${SO_CC_MACRO}} ${shell ${SO_CPP_MACRO}}
SO_CC_SOURCE      := ${strip ${SO_CC_SOURCE_NULL:null=}}

#-----------------------------------------------------------------------------
# Determine the object to build.
#-----------------------------------------------------------------------------

SO_OBJECTS_2 = \
	${SO_SOURCE:%.c=${OBJ_LOCATION}/%.o}

SO_OBJECTS_1 = \
	${SO_OBJECTS_2:%.cc=${OBJ_LOCATION}/%.o}

SO_OBJECTS = \
	${SO_OBJECTS_1:%.cpp=${OBJ_LOCATION}/%.o}

SO_DEPENDS = \
	${SO_OBJECTS:%.o=%.d}

LIB_OBJECTS_2 = \
	${LIB_SOURCE:%.c=${OBJ_LOCATION}/%.o}

LIB_OBJECTS_1 = \
	${LIB_OBJECTS_2:%.cc=${OBJ_LOCATION}/%.o}

LIB_OBJECTS = \
	${LIB_OBJECTS_1:%.cpp=${OBJ_LOCATION}/%.o}

LIB_DEPENDS = \
	${LIB_OBJECTS:%.o=%.d}

EXE_OBJECTS_2 = \
	${EXE_SOURCE:%.c=${OBJ_LOCATION}/%.o}

EXE_OBJECTS_1 = \
	${EXE_OBJECTS_2:%.cc=${OBJ_LOCATION}/%.o}

EXE_OBJECTS = \
	${EXE_OBJECTS_1:%.cpp=${OBJ_LOCATION}/%.o}

EXE_DEPENDS = \
	${EXE_OBJECTS:%.o=%.d}

#-----------------------------------------------------------------------------
# Targets.
#-----------------------------------------------------------------------------

DEFAULT_DEPENDENCIES = dirs SHOBJ LIB EXE

default:  all

all:  ${DEFAULT_DEPENDENCIES}

segment:
	${MAKE} dirs;
	${MAKE} LIB;
	${MAKE} SHOBJ;
	${MAKE} exe;

world: clean dirs shobj lib exe

#-----------------------------------------------------------------------------
# Rules.
#-----------------------------------------------------------------------------

shobj: SHOBJ

SHOBJ: ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}.${SO_MIN_NUM}.${SO_REV_NUM}

${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}.${SO_MIN_NUM}.${SO_REV_NUM}: ${SO_OBJECTS}
ifdef SO_NAME
 ifdef SO_CC_SOURCE
	  ${CCC} ${CCFLAGS} ${SO_LIBRARY_PATH} -shared -Wl,-soname,${SO_NAME}.${SO_MAJ_NUM} -o $@ ${SO_OBJECTS} ${SO_LIBS}
	  rm -f ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}
	  ln -s ${SO_NAME}.${SO_MAJ_NUM}.${SO_MIN_NUM}.${SO_REV_NUM} ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}
	  rm -f ${SO_LOCATION}/${SO_NAME}
	  ln -s ${SO_NAME}.${SO_MAJ_NUM} ${SO_LOCATION}/${SO_NAME}
 else
	  ${CC} ${CFLAGS} ${SO_LIBRARY_PATH} -shared -Wl,-soname,${SO_NAME}.${SO_MAJ_NUM} -o $@ ${SO_OBJECTS} ${SO_LIBS}
	  rm -f ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}
	  ln -s ${SO_NAME}.${SO_MAJ_NUM}.${SO_MIN_NUM}.${SO_REV_NUM} ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}
	  rm -f ${SO_LOCATION}/${SO_NAME}
	  ln -s ${SO_NAME}.${SO_MAJ_NUM} ${SO_LOCATION}/${SO_NAME}
 endif
endif

lib: LIB

LIB: ${LIB_LOCATION}/${LIB_NAME}

${LIB_LOCATION}/${LIB_NAME}: ${LIB_OBJECTS}
ifdef LIB_NAME
	${AR} ${AR_FLAGS} $@ ${LIB_OBJECTS}
	${RANLIB} $@
endif

exe: EXE

EXE: LIB ${EXE_LOCATION}/${EXE_NAME}

${EXE_LOCATION}/${EXE_NAME}: ${EXE_OBJECTS} ${EXE_LIBS}
	${CC_PRELINK}
ifdef EXE_NAME
 ifdef EXE_CC_SOURCE
	  ${CCC} ${CCFLAGS} ${LDFLAGS} -o $@ ${EXE_OBJECTS} ${EXE_LIBS} ${EXE_LIBS_SO} ${LIBS}
 else
	  ${CC} ${CFLAGS} ${LDFLAGS} -o $@ ${EXE_OBJECTS} ${EXE_LIBS} ${EXE_LIBS_SO} ${LIBS}
 endif
endif

TAGS: $(wildcard *.cpp) $(wildcard *.[ch])
	etags $^

dirs:
	@for i in \
	 ${OBJ_BASE} \
	 ${LIB_BASE} \
	 ${EXE_BASE} \
	 ${TESTR_BASE} \
	 ${OBJ_LOCATION} \
	 ${SO_LOCATION} \
	 ${LIB_LOCATION} \
	 ${EXE_LOCATION} \
	 ${TESTR_LOCATION} ; \
	do \
	  if [ ! -d $$i ]; \
	  then \
	    mkdir $$i; \
	    echo "$$i created"; \
	  fi; \
	done

clean:
	@for i in *~ %* *# .make* .cmake* .nse* core *.contrib* \
	 ${SO_OBJECTS} \
	 ${SO_DEPENDS} \
	 ${LIB_OBJECTS} \
	 ${LIB_DEPENDS} \
	 ${EXE_OBJECTS} \
	 ${EXE_DEPENDS} \
	 ${SO_LOCATION}/${SO_NAME} \
	 ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM} \
	 ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}.${SO_MIN_NUM}.${SO_REV_NUM} \
	 ${LIB_LOCATION}/${LIB_NAME} \
	 ${EXE_LOCATION}/${EXE_NAME} \
	 ${TESTR_LOCATION}/*.xml ; \
	do \
	  if [ -f $$i -o -h $$i ]; \
	  then \
	    rm -f $$i; \
	    echo "$$i removed"; \
	  fi; \
	done

install:
	@for i in \
	 ${SO_LOCATION}/${SO_NAME} \
	 ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM} \
	 ${SO_LOCATION}/${SO_NAME}.${SO_MAJ_NUM}.${SO_MIN_NUM}.${SO_REV_NUM} \
	 ${LIB_LOCATION}/${LIB_NAME} \
	 ${EXE_LOCATION}/${EXE_NAME} ; \
	do \
	  if [ -f $$i -o -h $$i ]; \
	  then \
	    cp -f $$i ${INSTALL_LOCATION}/.; \
	    echo "$$i installed"; \
	  fi; \
	done

#-----------------------------------------------------------------------------
# Pull in dependency files for existing .o files.
#-----------------------------------------------------------------------------

ifneq (${SO_DEPENDS},)
  -include ${SO_DEPENDS}
endif

ifneq (${LIB_DEPENDS},)
  -include ${LIB_DEPENDS}
endif

ifneq (${EXE_DEPENDS},)
  -include ${EXE_DEPENDS}
endif

#-----------------------------------------------------------------------------
# Suffix rules.
#-----------------------------------------------------------------------------

${OBJ_LOCATION}/%.o:	%.cc
	${CCC} ${CCFLAGS} -c -o $@ $<
	set -e; ${CCC} -MM ${CCFLAGS} $< | sed 's|\($*\)\.o[ :]*|\1.o $@ : |g' > ${OBJ_LOCATION}/$*.d; [ -s ${OBJ_LOCATION}/$*.d ] || rm -f ${OBJ_LOCATION}/$*.d

${OBJ_LOCATION}/%.o:	%.cpp
	${CCC} ${CCFLAGS} -c -o $@ $<
	set -e; ${CCC} -MM ${CCFLAGS} $< | sed 's|\($*\)\.o[ :]*|\1.o $@ : |g' > ${OBJ_LOCATION}/$*.d; [ -s ${OBJ_LOCATION}/$*.d ] || rm -f ${OBJ_LOCATION}/$*.d

${OBJ_LOCATION}/%.o:	%.c
	${CC} ${CFLAGS} -c -o $@ $<
	set -e; ${CC} -MM ${CFLAGS} $< | sed 's|\($*\)\.o[ :]*|\1.o $@ : |g' > ${OBJ_LOCATION}/$*.d; [ -s ${OBJ_LOCATION}/$*.d ] || rm -f ${OBJ_LOCATION}/$*.d

#-----------------------------------------------------------------------------
# Document generation rules
#-----------------------------------------------------------------------------

docs:
ifdef DOXYGEN_FILE
	doxygen $(DOXYGEN_FILE)
endif

#-----------------------------------------------------------------------------
# Handy testing targets.
#-----------------------------------------------------------------------------

test-style:
	@echo "PROJECT_HOME         = " ${PROJECT_HOME}
	@echo "BUILD_STYLE          = " ${BUILD_STYLE}
	@echo "BUILD_SUBDIR         = " ${BUILD_SUBDIR}
	@echo "BUILD_STYLE_FILE     = " ${BUILD_STYLE_FILE}
	@echo "SO_NAME              = " ${SO_NAME}
	@echo "SO_MAJ_NUM           = " ${SO_MAJ_NUM}
	@echo "SO_MIN_NUM           = " ${SO_MIN_NUM}
	@echo "SO_REV_NUM           = " ${SO_REV_NUM}
	@echo "LIB_NAME             = " ${LIB_NAME}
	@echo "EXE_NAME             = " ${EXE_NAME}
	@echo "MAKE                 = " ${MAKE}
	@echo "PWD                  = " ${PWD}
	@echo "DEFAULT_DEPENDENCIES = " ${DEFAULT_DEPENDENCIES}
	@echo "SO_LOCATION          = " ${SO_LOCATION}
	@echo "LIB_LOCATION         = " ${LIB_LOCATION}
	@echo "OBJ_LOCATION         = " ${OBJ_LOCATION}
	@echo "EXE_LOCATION         = " ${EXE_LOCATION}
	@echo "TESTR_LOCATION       = " ${TESTR_LOCATION}
	@echo "PWD_START            = " ${PWD_START}

test-flags:
	@echo "INCLUDE_PATH     = " ${INCLUDE_PATH}
	@echo "SO_LIBRARY_PATH  = " ${SO_LIBRARY_PATH}
	@echo "EXE_LIBRARY_PATH = " ${EXE_LIBRARY_PATH}
	@echo "CCFLAGS          = " ${CCFLAGS}
	@echo "CFLAGS           = " ${CFLAGS}
	@echo "LDFLAGS          = " ${LDFLAGS}
	@echo "ENV_FLAGS        = " ${ENV_FLAGS}

test-lists:
	@echo "SO_SOURCE      : " ${SO_SOURCE}
	@echo "LIB_SOURCE     : " ${LIB_SOURCE}
	@echo "EXE_SOURCE     : " ${EXE_SOURCE}
	@echo "EXE_CC_SOURCE  : " ${EXE_CC_SOURCE}
	@echo "SO_OBJECTS     : " ${SO_OBJECTS}
	@echo "LIB_OBJECTS    : " ${LIB_OBJECTS}
	@echo "EXE_OBJECTS    : " ${EXE_OBJECTS}
	@echo "SO_DEPENDS     : " ${SO_DEPENDS}
	@echo "LIB_DEPENDS    : " ${LIB_DEPENDS}
	@echo "EXE_DEPENDS    : " ${EXE_DEPENDS}
	@echo "SO_LIBS_PATH   : " ${SO_LIBS_PATH}
	@echo "EXE_LIBS_PATH  : " ${EXE_LIBS_PATH}

test-all: test-style test-lists test-flags

#
# End of build_master.mk.
#
