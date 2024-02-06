#!/bin/bash
set -e

export CWD=$(pwd)
export INSTALL_DIR="${CWD}/out"

if [[ "${1}" == "clean" ]]; then
    rm -rf ${INSTALL_DIR}
    exit 0
else 
    if [[ -d ${INSTALL_DIR} ]]; then
        rm -rf ${INSTALL_DIR}
    fi
    mkdir -p ${INSTALL_DIR}

    if [ "$(uname)" == "Darwin" ]; then
        export CURRENT_OS="MacOS"
    elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
        export CURRENT_OS="Linux"
    else 
        echo "current os is not supported."
        exit 0
    fi 

    bash ./crawler.sh
fi
