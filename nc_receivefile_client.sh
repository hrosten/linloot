#!/bin/bash

################################################################################

MY_NAME=$(basename $0)

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "Usage: $MY_NAME <ip> <port> <file> [pv]"
    exit 1
fi

ip=$1
port=$2
filename=$3
pv=$4

echo
echo "Start running the server on the sending end, e.g.:"
echo "  nc -nlvp $port < $filename"
echo "  pv -b $filename | nc -nlvp $port"
read -p "Press any key to continue..."

if [ "$pv" == "pv" ]; then
    nc -nv $ip $port | pv -b > $filename
else
    nc -nv $ip $port > $filename
fi
################################################################################
