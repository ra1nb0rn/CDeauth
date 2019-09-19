#!/bin/bash

# colors (from: https://stackoverflow.com/a/5947802)
GREEN="\033[0;32m"
SANE="\033[0m"
RED="\033[1;31m"

KERNEL=$(uname)
if [ "${KERNEL}" == "Darwin" ]; then
    echo -e "${GREEN}[+] Identified OS as: macOS --> using packet manager: brew${SANE}"
    brew update && brew install libpcap
elif [ "${KERNEL}" == "Linux" ]; then
    echo -e "${GREEN}[+] Identified OS as: Linux --> using packet manager: apt${SANE}"
    sudo apt-get update && sudo apt-get install libpcap-dev
else
    echo -e "${RED}[+] Could not install libpcap. If necessary, please do so manually${SANE}"
fi

make
./CDeauth
