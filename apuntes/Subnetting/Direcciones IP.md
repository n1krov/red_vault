> **Dirección IP** es una etiqueta numérica que identifica de manera lógica y jerárquica a una interfaz de red, como un dispositivo de computadora, laptop o teléfono inteligente conectado a una red que utiliza el protocolo de internet.

- Cuatro grupos de octetos (binarios)
- Direccion logica que identifica a tu dispositivo a traves de internet en tu red local
- Existen dos versiones principales: **IPv4**, con direcciones de 32 bits (como 192.168.1.1), y **IPv6**, con direcciones de 128 bits, diseñada para solucionar el agotamiento de direcciones IPv4.
- Hay 4 mil millones en ipv4 y 2^128 en ipv6

- Para conocer tu direccion ipv4 y ipv6:
```bash
ifconfig
```

- Con `bc` podemos realizar calculos:
```bash
echo "2^32" | bc
echo "obase=2; 192" | bc
echo "ibase=10; obase=2; 9" | bc
```
- Con `ibase` decimos cual es la base del numero actual, mientras que con `obase` queremos especificar que base de destino es. Por defecto si no se especifica es *decimal*

### Comandos utilizados
- [[ifconfig]]
- [[bc]]