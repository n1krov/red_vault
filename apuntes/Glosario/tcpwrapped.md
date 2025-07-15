## 🕵️‍♂️ ¿Qué significa `tcpwrapped`?

Cuando escaneás un puerto (por ejemplo con **Nmap**) y te muestra algo como:

```bash
PORT    STATE SERVICE  REASON
995/tcp open  pop3s    tcpwrapped
```

### 🔐 `tcpwrapped` = el puerto **está protegido** por el sistema (probablemente con un firewall o proxy) y **cerró la conexión inmediatamente si no confía en el cliente**.

---

## 🧠 Explicado fácil:

> El servidor **no respondió al escaneo de forma normal**, porque tiene una **capa extra de defensa**, y probablemente:
> - No reconoce al escáner (tu IP o cliente)
> - Espera una conexión segura con un cliente "real"
> - Tiene un firewall que **corta la conexión** si no ve tráfico válido

---

## 🔄 ¿Por qué pasa esto?

- El servicio está protegido con **TCP Wrappers**, un sistema viejo pero todavía usado (ej: `/etc/hosts.allow` y `/etc/hosts.deny`)
- O bien, el servidor tiene:
    - Fail2ban
    - Firewall (iptables, nftables)
    - Proxy inverso
    - IDS/IPS (como Snort o Suricata)

## 📌 En tu ejemplo:

```markdown
| **995** | POP3S    | _tcpwrapped_ |
```

- `995` = puerto seguro para recibir correos por **POP3 sobre SSL/TLS**
    
- `_tcpwrapped_` = el escaneo fue **bloqueado o interrumpido** antes de identificar bien el servicio
    

---

## ✅ ¿Cómo saber más?

- Intentá conectarte manualmente con `openssl`:
```bash
openssl s_client -connect mail.servidor.com:995
```
- O escaneá con más detalle:
```bash
nmap -p 995 -sV --script ssl-cert,ssl-enum-ciphers mail.servidor.com
```


[[glosario]]