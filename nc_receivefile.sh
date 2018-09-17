#!/bin/bash

################################################################################

MY_NAME=$(basename $0)

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $MY_NAME <port> <file> [pv]"
    exit 1
fi

port=$1
filename=$2
pv=$3

echo
echo "Run the client on the sending end, e.g:"
echo "  nc -nv MY_IP $port < $filename or"
echo "  pv $filename | nc -nv MY_IP $port"
echo
echo "Waiting for connection from the client..."

if [ "$pv" == "pv" ]; then
    nc -nlvp $port | pv -b > $filename
else
    nc -nlvp $port > $filename
fi

################################################################################
