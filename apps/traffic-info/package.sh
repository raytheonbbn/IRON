#!/bin/sh

# This script's name for error messages.
this="${0##*/}"
if [ -z ${IRON_HOME} ]; then
    echo ""
    echo "${this}: IRON_HOME is not set, please set it and re-run the script."
    echo ""
    exit 1
fi

VERSION_FILE="version.txt"
GIT_REV=`git rev-parse --short HEAD`
NOW=`date`
DATE_FILE=`date --date="${NOW}" +%y%m%d-%H%M`

NAME=traffic-info
START_SCRIPT=${NAME}.sh
TMP_DIR=/tmp/${NAME}
mkdir ${TMP_DIR}


cat <<EOF > ${TMP_DIR}/${VERSION_FILE}
git revision: ${GIT_REV}
date packaged: ${NOW}
EOF

PYTHON_DIR=${IRON_HOME}/python
cp -r \
    traffic-info.py \
    ${PYTHON_DIR}/iron \
    baseline-video-filters.csv \
    iron-video-filters.csv \
    ${TMP_DIR}
cp ${START_SCRIPT} /tmp/

tar -czvf ${NAME}-${DATE_FILE}.tar.gz -C /tmp --exclude="*.pyc" \
    --exclude="__pycache__" ${NAME} ${START_SCRIPT}

rm -rf ${TMP_DIR} /tmp/${START_SCRIPT}
