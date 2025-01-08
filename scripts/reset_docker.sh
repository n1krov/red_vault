#!/bin/bash
# script para eliminar volumenes imagenes contenedores
# autor: Z0SO
tput civis
trap ctrl_c INT

# colores
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
white='\033[0;37m'
nc='\033[0m'

function ctrl_c() {
    echo -e "\n${red}======== SALIENDO ========${nc}\n"
    tput cnorm
    exit 0
}

function main()
{
    echo -e "\n${yellow}[*] Eliminando contenedores...${nc}\n"
    docker rm $(docker ps -a -q) -f

    echo -e "\n${yellow}[*] Eliminando imagenes...${nc}\n"
    docker rmi $(docker images -a -q) -f

    echo -e "\n${yellow}[*] Eliminando volumenes...${nc}\n"
    docker volume rm $(docker volume ls -q) -f
}

echo -e "\n${cyan}======== DOCKER RESET ========${nc}\n"
main
echo -e "\n${cyan}======== SCRIPT FINALIZADO ========${nc}\n"
tput cnorm
