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


if [ ! -f $filename ]; then
    echo "[+] Error: file \"$filename\" not found"
    exit 1
fi

echo
echo "Run the client on the receiving end, e.g.:"
echo "  nc -nv MY_IP $port > $filename or"
echo "  nc -nv MY_IP $port | pv -b > $filename"
echo
echo "Waiting for connection from the client..."

if [ "$pv" == "pv" ]; then
    pv $filename | nc -nlvp $port
else
    nc -nlvp $port < $filename
fi

################################################################################
