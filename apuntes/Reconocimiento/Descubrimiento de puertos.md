A traves de un script

Libreria de bash:
```bash
#!/bin/bash
```

Funcion para salir de manera forzada:
```bash
function ctrl_c(){
	echo -e "\n\n[!] Saliendo..."
	tput cnorm; exit 1
}

trap ctrl_c SIGINT	
```

Declaracion de los puertos a escanear:
```bash
declare -a ports=(($seq 1 65535))
```

Funcion para escanear cada puerto
```bash
function checkport(){
	(3<> /dev/tcp/$1/$2) 2>/dev/null
	
	if [$? -eq 0]; then
		echo "[+] Host: $1 Port: $2 is (OPEN)"
	fi
	
	exec 3<&-
	exec 3>&-
}
```

Ocultamos el cursor:
```bash
tput civis
```

Iteramos por cada puerto 
```bash
if [$1]; then
	for port in ${ports[0]}; do
		checkport $1 $port & 
	done
else
	echo "\n[!] Uso $0 <ip-address>\n"
fi
```

Cerramos
```bash
wait
tput cnorm
```

Le damos permiso al programa para ejecutarse
```bash
chmod -x archivo.sh
./archivo.sh
```
### Pasos a seguir entonces
- declaramos los puertos
- iteramos por cada puerto
- chequeamos si el puerto esta activo
- cerramos y mostramos si es 0
