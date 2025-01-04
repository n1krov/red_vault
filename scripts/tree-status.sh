#/bin/bash

# Author:  Z0SO
# Este script tiene el objetivo de iterar sobre cada carpeta de un directorio, ingresar a cada una de ellas y mostrar el estado de git de cada una de ellas.

tput civis

# Colorines
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
END='\033[0m'
BLUE='\033[0;34m'

function ctrl_c() {
    echo -e "${RED}\n[!] Saliendo...${END}"
    exit 0
}

# trap del control+c
trap ctrl_c INT

echo -e "${BLUE}[*] Iniciando...${END}"


# Iterar sobre cada carpeta
for d in */ ; do
    echo -e "\n${GREEN}[*] Carpeta: ${d}${END}\n"
    # cd $d
    # git status
    # cd ..
   
    cd cosas-linux && gst | grep modified | tr -d '\t' | tr -d '*/'
done

echo -e "${BLUE}[*] Finalizado...${END}"



tput cnorm
