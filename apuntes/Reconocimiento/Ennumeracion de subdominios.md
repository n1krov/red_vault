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

- [Sublist3r](https://github.com/aboul3la/Sublist3r) es otra herramienta para ennumeracion de subdominios de forma pasiva, se aprovechar de informacion publica en la web para ello.
```
cd /opt
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
python3 setup.py install
pip install -r requirements.txt
python3 sublist3r -d tinder.com
```

## Herramientas
- [[phonebook]]
- [[ctfr]]
- [[gobuster]]
- [[wfuzz]]
- [[sublist3r]]