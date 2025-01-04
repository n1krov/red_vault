#!/bin/bash
# Script para resetar Docker
# Autor: Z0SO
tput civis

trap ctrl_c INT

# colores
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

function ctrl_c() {
    echo -e "\n${RED}[*] Saliendo...${NC}"
    tput cnorm
    exit 0
}

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[*] Este script debe ser ejecutado como root${NC}"
        exit 1
    fi
}

function check_docker() {
    if ! command -v docker &>/dev/null; then
        echo -e "${RED}[*] Docker no esta instalado${NC}"
        exit 1
    fi
}

function stop_containers() {
    echo -e "${GREEN}[*] Deteniendo contenedores...${NC}"
    docker stop $(docker ps -a -q) &>/dev/null
}

function remove_containers() {
    echo -e "${GREEN}[*] Eliminando contenedores...${NC}"
    docker rm $(docker ps -a -q) --force &>/dev/null
}

function remove_images() {
    echo -e "${GREEN}[*] Eliminando imagenes...${NC}"
    docker rmi $(docker images -a -q) --force &>/dev/null
}

function remove_volumes() {
    echo -e "${GREEN}[*] Eliminando volumenes...${NC}"
    docker volume rm $(docker volume ls -q) --force &>/dev/null
}

function reset_docker() {
    stop_containers
    remove_containers
    remove_images
    remove_volumes
    echo -e "${GREEN}[*] Docker reseteado con exito${NC}"
}

check_root
check_docker
reset_docker

tput cnorm
