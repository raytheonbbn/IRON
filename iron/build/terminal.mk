#=============================================================================
# terminal.mk
#
# Purpose:  Defines the project's selection of build styles and includes
#           build_master.mk.
#=============================================================================

#-----------------------------------------------------------------------------
# Set the build style.
#-----------------------------------------------------------------------------

BUILD_STYLE_DIR  := ${MAKE_HOME}
BUILD_STYLE_FILE := ${BUILD_STYLE_DIR}/${BUILD_STYLE}

FILE_TEST_CMD = if [ -f "${BUILD_STYLE_FILE}" ];\
then \
  echo found;\
else \
  echo not_found;\
fi

FILE_FOUND := $(shell ${FILE_TEST_CMD})

#-----------------------------------------------------------------------------
# Store the working directory.
#-----------------------------------------------------------------------------

CURRENT_PWD := $(shell pwd)
SRC_DIRS_PWD = ${CURRENT_PWD}

#-----------------------------------------------------------------------------
# 1. Make sure that BUILD_STYLE is defined as an environment variable.
# 2. Make sure that the BUILD_STYLE file actually exists.
# 3. Include BUILD_STYLE_FILE.
#-----------------------------------------------------------------------------

ifeq ($(strip $(BUILD_STYLE)),)
  BUILD_STYLE := ERROR : BUILD_STYLE is not a defined environment variable
else
  ifeq ($(FILE_FOUND),found)
    include ${BUILD_STYLE_FILE}
  else
    BUILD_STYLE_FILE := ERROR : ${BUILD_STYLE_FILE} does not exist
  endif
endif

#-----------------------------------------------------------------------------
# 1. Make sure that the project-wide build options file actually exists.
# 2. Include the project-wide build options file.
#-----------------------------------------------------------------------------

PROJECT_OPTIONS_FILE := ${PROJECT_HOME}/options.mk

FILE_TEST_CMD = if [ -f "${PROJECT_OPTIONS_FILE}" ];\
then \
  echo found;\
else \
  echo not_found;\
fi

FILE_FOUND := $(shell ${FILE_TEST_CMD})

ifeq ($(FILE_FOUND),found)
  include ${PROJECT_OPTIONS_FILE}
else
  PROJECT_OPTIONS_FILE := ERROR : ${PROJECT_OPTIONS_FILE} does not exist
endif

#-----------------------------------------------------------------------------
# Include the master build makefile.
#-----------------------------------------------------------------------------

include ${MAKE_HOME}/build_master.mk

#
# End of terminal.mk.
#
