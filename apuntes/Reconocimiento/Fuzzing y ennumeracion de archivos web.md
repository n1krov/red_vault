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

## Herramientas
- [[gobuster]]
- [[wfuzz]]
- [[fuff]]
- [[phonebook]]
- [[burpsuite]]