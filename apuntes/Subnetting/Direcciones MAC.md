> **Dirección MAC** es un identificador único de **48 bits** (6 bloques de dos caracteres hexadecimales) que corresponde de forma exclusiva a una tarjeta o dispositivo de red, también conocida como **dirección física**.

- Direccion fisica de un dispositivo de 48 bits.
- Es unico, pero se puede manipular
- 00:03:cc:34:32:bv es un ejemplo
- 00:03:cc --> **OUI**, identificador unico de la organizacion
- 34:32:bv --> **NIC**, controlador de la interfaz de red
- Los tres primeros grupos "00:03:cc" te dicen que tipo de dispositivo es o a que marca corresponde

- Para escanear todos los dispositivos de tu red:
```bash
arp-scan -I nombredetumaquina --localnet --ignoredups
```

- Para listar la direccion MAC y saber a que marca le pertenece:
```bash
macchanger -l
macchanger -l | grep -i vmware
```

### Comandos utilizados
- [[arp-scan]]
- [[macchanger]]