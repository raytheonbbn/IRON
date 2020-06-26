#! /usr/bin/env bash

SCRIPT_DIR=`dirname "$(readlink -f "$0")"`

# This is a LinkEm node, set it up as a bridge.
sudo ${SCRIPT_DIR}/../../scripts/deter_create_bridge.sh

# Exit script successfully.
exit 0

