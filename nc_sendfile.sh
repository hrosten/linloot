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

if [ ! -f $filename ]; then
    echo "[+] Error: file \"$filename\" not found"
    exit 1
fi

echo
echo "Start running the server on the receiving end, e.g.:"
echo "  nc -nlvp $port > $filename or"
echo "  nc -nlvp $port | pv -b > $filename"
read -p "Press any key to continue..."

if [ "$pv" == "pv" ]; then
    pv $filename | nc -nv $ip $port
else
    nc -nv $ip $port < $filename  
fi

################################################################################
