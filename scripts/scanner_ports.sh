#!/bin/bash

function ctrl_c() {
    echo -e "\n\n[!] Exiting...\n"
    tput cnorm # Mostrar cursor
    exit 1
}
trap ctrl_c INT
tputs civis # Ocultar cursor

for port in $(seq 1 65535); do
    ( echo '' > /dev/tcp/127.0.0.1/$port ) 2>/dev/null && echo -e "[*] Puerto >-> $port <-< ABIERTO"

done;
tput cnorm # Mostrar cursor

