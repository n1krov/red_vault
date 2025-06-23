
# Protocolo SMB (Server Message Block)

> **SMB** es un protocolo de **compartición de recursos** en red (archivos, impresoras, etc.) muy usado en entornos Windows, y en Linux a través de **Samba**.


## 🗂️ Analogía sencilla

Imagina un **archivo compartido** como un armario de oficina al que acceden varios usuarios:

- **Servidor** = el armario  
- **Cliente** = tú, que vas al armario a sacar o guardar documentos  
- **SMB** = las reglas y el “lenguaje” que usan para pedir permiso, abrir cajones y pasar hojas.

---

## ⚙️ ¿Cómo funciona, paso a paso?

1. **Descubrimiento**  
   - El cliente pregunta “¿Qué armarios (shares) hay disponibles en la red?”  
   - El servidor responde con la lista de carpetas/impresoras compartidas.

2. **Autenticación**  
   - Si la carpeta está protegida, el cliente envía usuario y contraseña.  
   - El servidor verifica identidad (puede usar Active Directory, local users, etc.).

3. **Operaciones de archivos**  
   - **Abrir** (`CREATE`)  
   - **Leer** (`READ`)  
   - **Escribir** (`WRITE`)  
   - **Cerrar** (`CLOSE`)

   Cada una de estas acciones es un “mensaje” SMB enviado entre cliente y servidor.

---

## 📡 Puertos más comunes

- **139/tcp** – SMB sobre NetBIOS (antiguo)  
- **445/tcp** – SMB directo sobre TCP/IP (versión moderna)

---

## 🌐 Ejemplos de uso

- Mapear una carpeta de Windows en Linux:  
```bash
  sudo mount -t cifs //192.168.1.50/Compartida /mnt/mi_carpeta \
       -o username=usuario,password=secreto
```

- En Windows “Conectar unidad de red” usando `\\servidor\Compartida`.
    

---

## ✅ Ventajas

- Integración nativa en Windows.
    
- Soporta permisos avanzados (ACLs).
    
- Permite compartir impresoras y servicios de anuncios (browse).
    

---

## ⚠️ Consideraciones

- Históricamente ha tenido vulnerabilidades; mantener versiones actualizadas (SMBv2/v3).
    
- Configurar cifrado si lo exponés fuera de tu LAN.
    

---

> **Resumen:**  
> SMB es el “idioma” que Windows (y Samba en Linux) usa para que máquinas comparten **carpetas**, **archivos** e **impresoras** de forma transparente en la red, gestionando permisos y acceso de modo muy parecido a abrir un armario compartido en tu oficina.


[[protocolos]]