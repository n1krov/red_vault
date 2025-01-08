#!/bin/bash
tput civis
trap ctrl_c INT

# script que escanea y reporta los hosts activos de una red mediante pings
# hecho por Z0SO

# colores
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

ctrl_c ()
{
   echo -e "${RED}[*] Saliendo...${NC}"
   tput cnorm
   exit 1
}

# como esta pensado para redes cn mascara /24 irian de redes x.x.x.1 a x.x.x.254
main ()
{
    echo -e "\n${CYAN}[*] Escaneando hosts activos en la red 192.168.1.x/24${NC}\n"

   for i in $(seq 1 254); do
       # timeout 1 bash -c "ping -c 1 192.168.1.$i" &>/dev/null && echo -e "\n${GREEN}Host 192.168.1.$i - ACTIVO${NC}\n" &
       for port in {21,22,23,25,80,443,445,3389}; do
           timeout 1 bash -c "echo '' >/dev/tcp/192.168.1.$i/$port" &>/dev/null && echo -e "${GREEN}Host 192.168.1.$i -> Puerto $port ABIERTO${NC}" &
       done
   done 
   
   # esperar a que terminen los procesos hijos 
   wait
}


main

tput cnorm
