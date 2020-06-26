#!/usr/bin/env bash

# This script's name for usage /error messages.
this="${0##*/}"

usage() {
    echo "Usage:"
    echo "  ${this} <pid to monitor> <log file>"
    exit 1
}

# Grab the command line arguments.
shift $(($OPTIND - 1))

if [ $# -ne 2 ]; then
    usage
fi

PID=$1
LOG_FILE=$2

pidstat -r -u -p ${PID} 1 1>${LOG_FILE} 2>&1

