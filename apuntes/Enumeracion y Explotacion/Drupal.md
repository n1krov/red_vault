> Drupal es un [sistema de gestión de contenidos](https://www.google.com/search?q=sistema+de+gesti%C3%B3n+de+contenidos&sca_esv=1224a207121717d4&sxsrf=AE3TifOgcuiGDeMI4kiBSo9GfnYJHZpxog%3A1766144467596&ei=0zlFaduUJMzO5OUPp8TE2Ao&ved=2ahUKEwjYsZuXz8mRAxXTBrkGHcbeCQUQgK4QegQIARAB&uact=5&oq=drupal&gs_lp=Egxnd3Mtd2l6LXNlcnAiBmRydXBhbDINEAAYgAQYsQMYQxiKBTIKEAAYgAQYQxiKBTIFEAAYgAQyChAAGIAEGEMYigUyBRAAGIAEMgUQABiABDIFEAAYgAQyChAAGIAEGEMYigUyBRAAGIAEMggQABiABBjLAUjCFlCTCFj4FHACeAGQAQOYAb8BoAGrCqoBBDAuMTG4AQPIAQD4AQGYAgmgAvcHqAIUwgIKEAAYsAMY1gQYR8ICDRAAGIAEGLADGEMYigXCAg8QABiABBiwAxhDGIoFGArCAgcQIxgnGOoCwgIWEC4YggYYgwYYJxj6BRjqAhjtBRjdBcICBxAuGCcY6gLCAg0QIxjwBRgnGMkCGOoCwgIQEAAYAxi0AhjqAhiPAdgBAcICEBAuGAMYtAIY6gIYjwHYAQHCAhYQLhjRAxgDGLQCGMcBGOoCGI8B2AEBwgIMECMYgAQYExgnGIoFwgIEECMYJ8ICChAuGIAEGCcYigXCAggQABiABBixA8ICEBAuGIAEGLEDGEMYgwEYigXCAhYQLhiABBixAxjRAxhDGIMBGMcBGIoFwgILEAAYgAQYsQMYgwHCAggQLhiABBixA8ICBRAuGIAEmAMU4gMFEgExICnxBTX8z9ZaQQJViAYBkAYKugYGCAEQARgKkgcFMi42LjGgB8RtsgcFMC42LjG4B9IHwgcFMi0yLjfIB2qACAA&sclient=gws-wiz-serp&mstk=AUtExfA2JD9-zPOVST-OZz3rVXvHODtoNTzCIaaMEAXqjk6y6Sd6uY7VuJ1bQ5W0rwQDzp_Cy1aDXEpfgDuDUFwibub6_4Bg5b37ts6lkPT4aWqDpttULgGz7qpoHebapORsDiaa4Kz8-90LP1g9avi1kI1D5aWX-1Xxres4dF-EwsuPnPo&csui=3) (CMS) de código abierto, gratuito y altamente flexible, escrito en PHP y basado en LAMP. Destaca por su arquitectura modular, alta seguridad y escalabilidad, ideal para sitios web complejos, institucionales y empresariales que requieren personalización avanzada.

## Herramientas
- [[droopescan]]

## Caso practico
Utilizaremos el repo [[vulhub]]
```bash
cd vulhub/drupal/CVE-2018-7600
docker compose up -d
```
Entramos a la web y nos logueamos.

- Primer escaneo:
```bash
whatweb http://127.0.0.1:8080
```

## Droopscan
Escaneo basico:
```bash
droopscan scan drupal --url http://localhost:8080
```

- En esta maquina en particular hay una vulnerabilidad por una ruta donde podemos cambiar la contrasenia en caso que nos la hayamos olvidado, pero utiliza tecnicas de explotacion avanzada por lo que veremos mas adelante.