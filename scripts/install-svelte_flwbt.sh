#!/bin/bash

tput civis

function ctrl_c() {
    tput cnorm
    echo -e "\n${red}[-]${end} ${yellow}Saliendo...${end}"
    exit 0
}

trap ctrl_c INT

# colores

readonly red='\033[1;31m'
readonly green='\033[1;32m'
readonly yellow='\033[1;33m'
readonly blue='\033[1;34m'
readonly purple='\033[1;35m'
readonly cyan='\033[1;36m'
readonly white='\033[1;37m'
readonly end='\033[0m'

# comprobamos si el usuario es root
function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${red}Este script debe ejecutarse como root${end}" 1>&2
        tput cnorm
        exit 1
    fi
}

function bienvenida() {
    clear
    echo -e "    ----------------------[Z0SO]----------------------" 
    echo -e "    ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡙⣻⣿⣿⣿⣿⣷"
    echo -e "    ⣿⣿⣿⣿⣿⣿⣿⠟⠋⠁⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡝⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⢿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠘⢿⣿⣯⠻⣿⣿⣄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⡀⠙⢿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡍⢻⣿⣿⣿⣿⣿⣮⣿⣿⣧⠈⢿⣿⣷⡝⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⣿⣶⣴⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡟⣿⣿⣿⣿⣿⡈⢿⣿⣿⣿⣿⣗⠈⢿⣿⣷⡈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⠻⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⢻⣿⢻⣿⣿⣧⡈⢻⣿⣿⣿⣿⣅⠈⢿⣿⣷⣄⣿⣿⣿⣿⡟⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⣶⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠘⣿⡀⢻⣿⣿⡧⡀⠹⣿⣿⣿⣷⡀⠚⢿⣿⡄⠀⠙⣿⣿⣿⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⣿⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡀⢹⣧⠈⢿⣿⣿⢱⠀⠈⢿⣿⣿⡇⠀⠈⢿⡷⠀⠀⠘⢿⣿⡇⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠘⣿⠂⠈⢿⣿⡇⢣⠀⠀⠻⣿⡷⠀⠀⠈⣷⡄⠀⠀⢈⣻⣇⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⣿⠀⠀⠀⠀⠀⠀⠀⠀⠐⠋⠉⠉⠀⠀⠀⡇⠀⢻⠄⠀⠀⠻⣿⡀⢇⠀⠀⠙⢇⣠⠾⢋⣹⣶⣾⣿⣿⣿⣿⣿⣿⠛⢿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣆⠀⠀⠀⠹⣧⠈⢆⠀⠀⠞⣡⣾⣿⠿⠛⣻⣷⣾⡿⠿⠿⠧⢄⣸⠻⣿⣿⣿⣿⣿"
    echo -e "    ⣽⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠿⠀⠀⠀⠀⠘⠆⠈⠁⠀⠈⠉⠀⠘⠶⠻⠏⠉⠀⠀⠀⠀⠀⠀⢹⡄⣿⣿⣿⣿⣿"
    echo -e "    ⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣖⣚⣛⣛⣟⣒⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠈⡇⣿⣿⣿⣿⣿"
    echo -e "    ⣿⣆⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⠿⣿⣿⣿⣿⡟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡠⠒⠉⠀⠀⡅⢹⣿⣿⣿⣿"
    echo -e "    ⣿⣿⡀⠀⢀⣴⣿⠿⠛⣛⣿⣿⣾⡿⠏⠁⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⢸⣿⣿⣿⣿"
    echo -e "    ⣿⣿⣅⢰⡿⠋⠀⠐⣾⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⢀⢸⣿⣿⣿⣿"
    echo -e "    ⠁⠈⠹⣯⠁⠀⠴⠋⠀⠀⡠⠂⢀⠴⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠤⢴⣿⡆⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿"
    echo -e "    ⢻⡟⢲⣌⣳⡀⠀⠀⡡⠊⠀⠴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡠⠤⠒⠂⣉⣤⣤⣴⡿⠿⣿⠀⠀⠀⠀⠀⢰⢸⣿⣿⣿⣿"
    echo -e "    ⠈⡇⣸⠉⢻⢿⡇⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠤⠖⠊⣉⣀⠤⠔⠒⠉⠁⠀⠈⢿⣗⠀⡟⠀⠀⠀⠀⠀⢸⣾⣿⣿⣿⣿"
    echo -e "    ⣦⠁⠹⣦⠘⢄⣙⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⣶⣿⣶⣶⠖⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⡹⠁⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿"
    echo -e "    ⣿⣷⣄⠈⠓⢤⣬⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⠅⠈⣿⡀⠀⠀⠀⠀⠀⠀⠀⢀⣠⡴⠞⢁⠜⠀⠀⠀⠀⠀⣠⢿⣿⣿⣿⣿⣿⣿"
    echo -e "    ⢿⣿⢻⣷⣤⣀⡈⠁⠈⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠣⣔⠉⠳⣶⣤⠄⣀⣠⠴⠞⢛⡩⠤⠚⠁⠀⠀⠀⠀⢀⣼⣧⠀⢻⣿⣿⣿⣿⣿"
    echo -e "    ⢸⣿⢸⣿⣿⣿⣿⣷⣶⣶⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠑⠒⠛⠓⠒⠒⠊⠉⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣼⡆⢸⣿⣿⣿⣿⣿"
    echo -e "    ⠸⣿⢸⣿⣿⣿⣿⣿⣿⣿⠿⠋⢻⢶⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⠟⢹⣯⣿⡇⢸⠸⣿⣿⣿⣿"
    echo -e "    ⠀⣿⣿⣿⣿⣿⠿⢿⡏⠁⠀⠀⡌⠈⠟⣌⠙⠲⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣴⠟⠋⠀⢀⣿⣿⣿⣷⡈⠀⠛⣿⣿⣿\n"

    echo -e "\n${green}[+]${end} ${cyan}Bienvenido al instalador de FLWBT${end}"
    
    sleep 3

}


function main() {
    clear
    echo -e "\n${green}[+]${end} ${cyan}Instalando dependencias...${end}"

    npm install

    echo -e "\n${green}[+]${end} ${cyan}Instalando tailwindcss...${end}"
    npx svelte-add@latest tailwindcss
    npm i
    
    echo -e "\n${green}[+]${end} ${cyan}Instalando FLWBT...${end}"
    npm i -D flowbite-svelte flowbite flowbite-svelte-icons

    clear

    echo -e "\n${green}[+]${end} ${cyan}Modificando archivo tailwind.config.js...${end}"

    rm -rf tailwind.config.js 
    my_script=$(curl GET "https://raw.githubusercontent.com/Z0SO/gy/refs/heads/master/client/README.md" | awk "/\`\`\`js/ , /as Config/" | tr -d "\`\`\`js")
    echo "$my_script" > tailwind.config.js

    echo -e "\n${green}[+]${end} ${cyan}Instalación completada${end}"

}


check_root

bienvenida

main

tput cnorm
