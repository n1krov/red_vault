#!/bin/bash
tput civis

function ctrl_c()
{
    echo -e "\n\n[!] Saliendo...\n"
    tput cnorm
    exit 1
}

trap ctrl_c INT

check_port()
{
    (exec 3<> /dev/tcp/$1/$2) &>/dev/null
    if [ $? -eq 0 ];then
        echo -e "\n[+] Host $1 - Puerto $2 abierto"
    fi

    exec 3>&-
    exec 3<&-
}


# declaramos un array para los puertos
declare -a ports=( $(seq 1 65535) )


if [ $1 ];then
    for port in ${ports[@]};do
        check_port $1 $port &
    done
else
    echo -e "\n[!] Uso: $0 <IP>\n"
    tput cnorm
    exit 1
fi

tput cnorm

# usamos wait para esperar a que todos los procesos hijos terminen
wait
