
# 🕵️‍♂️ `nslookup` - Guía Rápida  
*Herramienta para consultas DNS desde la terminal (Windows/Linux/macOS).*

## 🔍 **Consultas Básicas**
```bash
nslookup ejemplo.com             # Consulta A (IPv4)
nslookup -type=AAAA ejemplo.com  # Consulta IPv6
nslookup -type=MX ejemplo.com    # Consulta servidores de correo
nslookup -type=NS ejemplo.com    # Consulta servidores DNS autoritativos
nslookup -type=TXT ejemplo.com   # Consulta registros TXT (ej: SPF, DKIM)
```

## 🎯 **Consultas Avanzadas**
```bash
nslookup ejemplo.com 8.8.8.8       # Usa DNS específico (Google DNS)
nslookup -debug ejemplo.com        # Muestra detalles técnicos de la consulta
nslookup 142.250.190.78            # Consulta PTR (DNS reverso)
nslookup -query=SOA ejemplo.com    # Información de zona DNS
```

## 💻 **Modo Interactivo**
```bash
nslookup
> server 1.1.1.1        # Cambia DNS a Cloudflare
> set type=MX           # Configura tipo de registro
> ejemplo.com           # Ejecuta consulta
> exit                  # Salir
```

## 🛠️ **Trucos Útiles**
- **Obtener solo la IP** (Linux/macOS):
  ```bash
  nslookup ejemplo.com | grep -m1 Address | awk '{print $2}'
  ```
- **Consultar múltiples dominios**:
  ```bash
  for dom in google.com github.com; do nslookup $dom; done
  ```
- **Ver timeout y reintentos**:
  ```bash
  nslookup -timeout=10 -retry=3 ejemplo.com
  ```

## ⚠️ **Limitaciones**
- No soporta consultas DOH (DNS over HTTPS) como `dig` o `curl`.
- En Linux, considera usar `dig` o `host` para opciones más avanzadas.

## 🔗 **Alternativas Modernas**
```bash
dig ejemplo.com +short             # Más rápido y preciso (Linux/macOS)
curl https://dns.google/resolve?name=ejemplo.com  # DNS over HTTPS
```

---

**📌 Nota:** Usa `nslookup /?` (Windows) o `man nslookup` (Linux/macOS) para ver todas las opciones.  

[[herramientas]]