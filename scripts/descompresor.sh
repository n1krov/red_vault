#!/bin/bash

# script de descompresión de archivos recursivo


function ctrl_c() {
    echo -e "\n\n[+] Saliendo del script..."
    exit 1
}



trap ctrl_c INT

first_file_name="test"


# descomprimido almacena el nombre del archivo descomprimido
descomprimido="$(7z l $first_file_name | tail -n 3 | head -n 1 | awk 'NF{print $NF}')"
echo ''
echo -e "[+] El primer archivo a descomprimir es: $first_file_name\n"
echo -e "[+] El archivo descomprimido es de $first_file_name es: $descomprimido\n\n"

7z x $first_file_name &>/dev/null

while [ $descomprimido ]; do

    
    echo -e "\n[+] Descomprimiendo archivo: $descomprimido" 
    
    7z x $descomprimido &>/dev/null 

    descomprimido="$(7z l $descomprimido 2>/dev/null | tail -n 3 | head -n 1 | awk 'NF{print $NF}')"
    
done

echo -e "\n[+] Todos los archivos han sido descomprimidos\n"
echo -e "\n[+]-------------------------------------------\n"

ultimo_archivo="$(cat data9.bin)"

echo -e "\n[+] El último archivo es: $ultimo_archivo\n"
