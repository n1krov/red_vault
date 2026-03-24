> Para hacer el analisis de una pagina y encontrar vulnerabilidades no podemos hacerlas al azar, es ilegal. Pero podemos ocupar sitios que recompensan el hallar fallas en un sistema. 

## Hacktivity
- Ir a [Hacktivity](https://hackerone.com/hacktivity/overview?queryString=disclosed%3Atrue&sortField=latest_disclosable_activity_at&sortDirection=DESC&pageIndex=0) 
- Te creas una cuenta y en la pestania `Hacktivity` podes ver la actividad reciente de vulnerabilidades encontradas y cuanto gano el hacker que hallo esa falla.
- En la pestania `Discover` podemos buscar una empresa que nos interese y leer su caso. Detalla el scope, que es lo que tenemos permitido hacer, subdominios que podemos analizar, etc.

---
## Descubriendo Emails
> El primer paso para hallar vulnerabilidades de una pagina web puede ser a traves de las personas. Analizando emails.
### Paginas para listar correos
Buscamos segun los dominios `tinder.com` y salen una banda.
- https://hunter.io/
- https://intelx.io/ - este es potente pero hay que pagar
- https://phonebook.cz/ - este es gratis

### Extension de Chrome para Gmail
Con este extension podemos buscar por posiciones como CEO, Engineering, etc, desde gmail.
- Clearbit

### Para verificar una cuenta de correo electronico
Una vez que obtenemos los correos podemos verificar si son reales o estan vigentes en estas paginas:
- https://www.verifyemailaddress.org/
- https://email-checker.net/

---
## Reconocimiento con imagenes
Una vez que obtengamos correos podemos acceder a sus redes sociales y con una foto es suficiente para averiguar mas. En esta pagina subimos esa foto y nos muestra mediante reconocimiento facial en que otras plataformas hay fotos similares:
- https://pimeyes.com/es

---
## Ennumeracion de subdominios
> Los dominios o subdominios son las diferentes rutas que se crean para mostrar diferentes recursos cualquier pagina web. Puede ser que una empresa no haya protegido lo suficiente alguna url que compromete datos.
### Por web
- Podemos usar **Phonebook**

### Por consola
- Repositorio de github [ctfr](https://github.com/UnaPibaGeek/ctfr) para hacer una ennumeracion de subdominios de forma pasiva

```bash
cd /opt
git clone https://github.com/UnaPibaGeek/ctfr
cd ctfr
pip3 install -r requirements.txt
python3 ctfr.py -d tinder.com
```

- [Gobuster](https://github.com/OJ/gobuster) es una herramienta agresiva, escrita en Go permite mucha velocidad para descubrimiento de subdominios
```bash
gobuster vhost -u https://tinder.com  -w ruta/al/diccionario/SecLists -t 20
```
- Esta herramienta necesita de diccionarios, uno que puedes usar es [SecLists](https://github.com/danielmiessler/SecLists), te lo clonas en `/usr/share/` y sirve un monton.
```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
```

- [wfuzz](https://github.com/xmendez/wfuzz) es otra herramienta de reconocimiento activo
```
wfuzz -w /usr/share/SecLists/DNS/Discovery/diccionario-50000.txt -t 20 -H "FUZZ.tinder.com" https://tinder.com
```
- `--hc=403` esconder los errores 403-forbidden
- `--sc=200` mostrar los codigos 200-OK

- [Sublit3r](https://github.com/aboul3la/Sublist3r) es otra herramienta para ennumeracion de subdominios de forma pasiva, se aprovechar de informacion publica en la web para ello.
```
cd /opt
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
python3 setup.py install
pip install -r requirements.txt
python3 sublist3r -d tinder.com
```

---
## Credenciales y brechas de seguridad
> Mediante [Dehashed](https://dehashed.com/) y el email de una persona podemos saber en que sitios se logueo con el mismo y en ocasiones podemos ver la contrasenia o pagar para verla.

- Podemos valernos de paginas como [Linkedin](https://linkedin.com/) donde se pueden ver quienes trabajaron, trabajan en una empresa y abrirse camino a partir de recoleccion publica de informacion de las personas.

---
## Tecnologia en una web
> Conocer que tecnologia utiliza una pagina web me sirve para conocer la estructura sobre la cual se basa y que versiones tienen pueden contener vulnerabilidades
### Herramientas
- [whatweb](https://github.com/urbanadventurer/WhatWeb) se vale de informacion de ficheros y demas, es pasiva
```
whatweb https://miwifi.com
```

- `Wappalyzer` es una extension de Chrome que si entras a una pagina web y pinchas en esta extension te dice las tecnologias que utiliza y su version.

- [builtwith](https://builtwith.com/) es una pagina web que al colocarle la direccion que quieras te devuelve muchisima informacion acerca de las tecnologias que utiliza.

---
## Fuzzing y ennumeracion de archivos web
>_Fuzz testing_, or _fuzzing_, is a software testing technique aimed at identifying bugs, vulnerabilities, or unexpected behavior by automatically providing a program with unexpected, malformed, or semi-malformed inputs.

### Herramientas
- **Gobuster**
```
gobuster dir -u https://miwifi.com -w /usr/share/SecLists/Discovery/Web-Content/directory-list.txt -t 200 
```
- `--add-slash` para visualizacion nomas
- `-b 403,404` excluye las rutas que devolvieron un 403 o 404
- `-x html,php,txt` filtra tambien por tipo de archivo
- `-s 200 -b ''` inidicas que quieres ver rutas con codigo de estado 200-OK y blacklist cadena vacia, sino da error

- **wfuzz**
```
wfuzz -c -t 200 --hc=404,403 -w archivo/de/palabras/spec/lists https://miwifi.com/FUZZ/
```
- la palabra FUZZ al final de la url es para indicar que cada palabra que estamos probando del diccionario se coloque en esa parte
- `--sl=216` me muestra rutas que contengan en la respuesta 216 lineas
```
wfuzz -c -t 200 --hc=404,403 -z file,archivo/de/palabras/spec/lists https://miwifi.com/FUZZ/
```
- En vez de usar la lista de palabras lo convierte a diccionario, es otra forma de mapear
```
wfuzz -c -t 200 --hc=404,403 -w archivo/de/palabras/spec/lists -z list,html-txt-php https://miwifi.com/FUZZ.FUZZZ
```
- Ennumerar archivos con extension `html-txt-php`
```
wfuzz -c --hc=404 -t 200 -z range,1-20000 'https://miwifi.com/product?id=FUZZ'
```
- Ennumerar productos por rangos `-z range,1-20000`

- [ffuf](https://github.com/ffuf/ffuf) es otra herramienta hecha en go, similar a wfuzz pero mas rapida
```
ffuf -c -mc=200 -t 200 -w diccionario/de/palabras -u https://miwifi.com/FUZZ/ 
```

- **phonebook** sigue siendo otra alternativa para ennumerar urls

- **burp suite** es una herramienta de analisis de trafico
	- A traves de un proxy **foxy proxy**, extension de chrome o firefox, se puede interceptar el trafico
	- funciona como un proxy o intermediario entre la peticion y la respuesta del servidor. ves que mandas y que responde.

---
`Extra`
- **upx** para reducir el tamanio de archivos go

---
## Reconociendo SO

- Ping tiene una variable ttl (time to live) que nos puede ayudar a identificar el sistema operativo
```
ping -c 1 192.168.100.1
```
- ttl=64 -  generalmente linux
- ttl=128 - generalmente windows