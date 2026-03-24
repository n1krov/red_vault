> **SMB ([Server Message Block](https://www.google.com/search?q=Server+Message+Block&sca_esv=a0bb12506671175f&sxsrf=AE3TifO-mEl3P1jC7oGHbyQ9QPLTw2n7RA%3A1765743831796&ei=1xw_acKsMO--5OUP_q2I6Qk&ved=2ahUKEwjY8pXw972RAxWiFrkGHUPxEicQgK4QegYIAQgAEAM&uact=5&oq=smb&gs_lp=Egxnd3Mtd2l6LXNlcnAiA3NtYjIFEAAYgAQyBRAAGIAEMgUQABiABDIFEAAYgAQyBRAAGIAEMgUQABiABDIFEAAYgAQyBRAAGIAEMgsQLhiABBjRAxjHATIMEAAYgAQYsQMYChgLSJ8VUPEGWJ0ScAJ4AZABApgBYqABqAiqAQIxMrgBA8gBAPgBAZgCBaACpwOoAhTCAgoQABiABBgKGMsBwgIIEAAYgAQYogTCAgUQABjvBcICBxAjGCcY6gLCAhYQLhiCBhiDBhgnGPoFGOoCGO0FGN0FwgIHEC4YJxjqAsICEBAAGAMYtAIY6gIYjwHYAQHCAhAQLhgDGLQCGOoCGI8B2AEBwgIKECMYgAQYJxiKBcICChAuGIAEGCcYigXCAgoQABiABBhDGIoFwgIKEC4YgAQYQxiKBcICCxAAGIAEGLEDGIMBwgIIEAAYgAQYsQPCAhQQLhiABBixAxiDARjHARiOBRivAcICDhAuGIAEGMcBGI4FGK8BmAMS4gMFEgExICniAwUSATEgQPEFjdS3jj2-JxOIBgG6BgYIARABGAqSBwMzLjKgB7GyAbIHAzIuMrgHlAPCBwUyLTEuNMgHPoAIAA&sclient=gws-wiz-serp))** **es un protocolo de red fundamental para compartir recursos como archivos, impresoras y puertos serie en una red local**, especialmente popular en entornos Windows pero compatible con Linux y macOS a través de implementaciones como Samba, permitiendo la comunicación cliente-servidor para acceder a carpetas y servicios como si fueran locales, siendo un pilar de las redes Microsoft desde los años 80.

# Samba =! SMB

## Herramientas
- [[smbclient]]
- [[smbmap]]
- [[cracmapexec]]

## Caso practico
```
cd vulhub/samba/CVE-2017-7494
docker compose up -d
```
Luego probamos la siguiente instruccion:
`smbclient -L 127.0.0.1 -N`
Podemos probar con otra herramienta
`smbmap -H 127.0.0.1`
Para ingresar a alguno de los recursos listados:
`smbclient //127.0.0.1 -N`
Podemos subir archivos ahora con:
`put archivo.txt`
Para descargar ese recurso
`get archivo.txt`