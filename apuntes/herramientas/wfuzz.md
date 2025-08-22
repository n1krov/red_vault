
Es una herramienta de fuzzing hecha en python

aqui un ejemplo de su uso ultilizando rangos

```sh
wfuzz -c -X POST -t 200 -z range,1-1500 -d 'pdf_id=FUZZ' http://localhost:5000/download  
```
-c es para el color
-X POST se indica el tipo de solicitud http
-t para indicar los hilos, en este caso tiene 200
-z es el payload, en este caso es un rango d e 1 a 1500
-d es la data que se va a modificar, en este caso donde dice FUZZ es donde va a ser reemplazado por el payload
y por ultimo se tira la URL

por ahi si quieres filtrar cantidad de caracteres, puedes hacerlo con 
`--hh=<cant>,<otra_cant>`

filtrar tambien por numero de lineas
`--hl=101`



