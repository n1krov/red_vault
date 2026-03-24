> Magento es una **plataforma de comercio electrónico de [código abierto](https://www.google.com/search?q=c%C3%B3digo+abierto&sca_esv=1224a207121717d4&sxsrf=AE3TifN7jV-Eq54Of6ZIwFJiNK3kKud-5Q%3A1766147023514&ei=z0NFaZOUH9fM5OUPu9ybwA8&ved=2ahUKEwjkj_Sx0smRAxXIBbkGHQARJgIQgK4QegQIARAC&uact=5&oq=magento&gs_lp=Egxnd3Mtd2l6LXNlcnAiB21hZ2VudG8yBxAAGIAEGAoyBRAAGIAEMgwQABiABBixAxgKGAsyCRAAGIAEGAoYCzIFEAAYgAQyCRAAGIAEGAoYCzILEC4YgAQY0QMYxwEyCRAAGIAEGAoYCzIFEAAYgAQyCRAAGIAEGAoYC0i1FlC7BFidFHADeAGQAQSYAY4BoAGJDKoBBDIuMTK4AQPIAQD4AQGYAgmgAskGqAISwgIKEAAYsAMY1gQYR8ICDRAAGIAEGLADGEMYigXCAhkQLhiABBiwAxjRAxhDGMcBGMgDGIoF2AEBwgIKEAAYgAQYQxiKBcICCBAAGIAEGMsBwgIHECMYJxjqAsICFhAuGIIGGIMGGCcY-gUY6gIY7QUY3QXCAgcQLhgnGOoCwgINECMY8AUYJxjJAhjqAsICFhAAGIAEGEMYtAIY5wYYigUY6gLYAQLCAh8QLhiABBjRAxhDGLQCGOcGGMcBGMgDGIoFGOoC2AECwgIhEC4YgAQY0QMYQxi0AhjnBhjHARjIAxiKBRjqAhgK2AECwgIKECMYgAQYJxiKBcICChAuGIAEGCcYigXCAhAQIxjwBRiABBgnGMkCGIoFwgIQEC4YgAQY0QMYxwEYJxiKBcICCBAAGIAEGLEDwgIOEC4YgAQYsQMY0QMYxwHCAg4QLhiABBixAxiDARiKBcICBBAAGAPCAgUQLhiABMICCBAuGIAEGLEDwgILEC4YgAQYxwEYrwHCAgoQLhiABBhDGIoFmAMQ4gMFEgExICnxBaH0bXxNBSD_iAYBkAYLugYECAEYCLoGBggCEAEYAZIHAzMuNqAH3KwBsgcDMC42uAeRBsIHBTMtNy4yyAeLAYAIAA&sclient=gws-wiz-serp&mstk=AUtExfANJgugaar4NaA7A6Ck-bnWPAOhugmL02wY8gxN48O5EAkZ60vObaET_OgfWg1lpCM8eXs_PpA-wuAKzveu-KIfE1lfxGW-D5FobrFwRIRyYCzgYkjzfniKkFz84JmLFPoGn6E-fF8eUI70Wjdpc_9KYBXePYLz6SS4J2bM_xvhV67iX6ImqCPSMm11wQHC2mvCLWgUMwP-IotmU5N9jxC6COUqulOUAbnkrD5rAY8T0r6D2kKq0QlF0f_4AZUW10LaknRjW913XOU6AYK1_8wq&csui=3) (PHP) altamente personalizable y escalable**, propiedad de [Adobe](https://business.adobe.com/es/products/commerce/magento.html). Ideal para grandes volúmenes de tráfico y B2B/B2C, permite gestionar inventarios, clientes y funciones avanzadas de e-commerce, ocupando cerca del 30% del mercado mundial.

## Herramientas
- [[magescan]]

## Caso practico
Utilizamos el proyecto [[vulhub]]
```bash
cd vulhub/magento/2.2-sqli
docker compose up -d
```

Hacemos el proceso de instalacion en http://localhost:8080.  
- Para explotar una vulnerabilidad podemos ir al repositorio de vulhub/magest/2.2sqli y leyendo nos encontramos con un PHOC que es un script de python que podemos descargarlo y ejecutarlo.
```bash
python3 magento-sqli.py http://localhost:8080/
```
- Esto te devuelve la cookie de una sesion activa.

Dentro de otro navegador (NO BRAVE) descargamos una extension Cookie Editor y dentro del mismo navegador entramos a `http://localhost:8080/admin/` para ir al panel de administracion y con la extension deberia aparecer una cookie de `admin` alli cambiamos la cookie por la que obtuvimos del script de python. Y logramos acceder a la sesion del mismo administrador solo con la cookie.

## Mage scan
Escaneo basico
```
php magescan.phar scan:all https://127.0.0.1:8080
```



