
# Enumeracion de Gestores de contenido
## WordPress
### Enumeracion de usuarios

Primero se debe identificar el xmlrpc.php, el cual se encuentra en la raiz del sitio web. Para ello se puede utilizar el siguiente comando:

```bash
curl -s -X POST http://<IP>/xmlrpc.php
```

Hay dos archivos xml aca, uno para enumerar los metodos y otro para ir probando por fuerza brutga los usuarios. Para ello se puede utilizar el siguiente comando:

probar con curl para enumeracion de metodos
```bash
curl -X POST http://<IP>/xmlrpc.php -d @method_enum.xml
```

probar con curl para autenticacion por fuerza bruta
```bash
 curl -X POST http://localhost:31337/xmlrpc.php -d@brute_force.xml
```

Tambien hay un script en bash de lo aprendido que hace fuerza bruta de manera automatica

