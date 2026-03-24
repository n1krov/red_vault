> Ennumeracion de certificados ssl en paginas web HTTP y HTTPS
## Herramientas
- [[whatweb]]
- [[wfuzz]]
- [[fuff]]
- [[gobuster]]
- dirb
- dirbuster
- dirsearch
- [[openssl]]
- [[sslscan]]

## Escaneo
- Inicialmente iriamos por averiguar que tipo de [[Tecnologia en una web]].
- Luego intentariamos ataques de fuerzas bruta con Herramientas como las listadas.
## Descubrir que tipo de certificado tiene la web
- Un certificado SSL **es un archivo digital que autentica la identidad de un sitio web y encripta la información enviada entre el navegador y el servidor (HTTPS), garantizando privacidad y seguridad**. Es esencial para proteger datos sensibles, generar confianza en los usuarios y mejorar el posicionamiento en buscadores, mostrando el candado de seguridad.
- `openssl s_client -connect tinder.com:443`
- `sslscan tinder.com`

---
## Laboratorio
- [[Heartbleed]]