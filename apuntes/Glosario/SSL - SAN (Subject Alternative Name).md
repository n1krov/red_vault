## 🧠 ¿Qué es un SAN?

**SAN = Subject Alternative Name**

Permite que un único certificado SSL sea válido para:

- **Varios dominios distintos** (multidominio)
    
- **Subdominios con `*`** (wildcards)
    

Ejemplo:

```txt
SANs: 
  - chaco.gob.ar
  - *.chaco.gob.ar
  - *.ecomchaco.com.ar
```

🔐 Esto ahorra dinero y facilita la administración.

---

## 🔎 Puertos comunes que usan SSL/TLS

|Puerto|Protocolo|Servicio|
|---|---|---|
|443|HTTPS|Web segura|
|465|SMTPS|Envío de mails cifrado|
|587|SMTP+STARTTLS|Envío con upgrade a TLS|
|993|IMAPS|IMAP sobre TLS|
|995|POP3S|POP3 sobre TLS|

> Todos ellos pueden usar el **mismo certificado SSL** si están en el mismo host.

---

## ⚠️ Consideraciones de seguridad

- Si se **compromete la clave privada** → todos los servicios/dominios están en riesgo
    
- Puede revelar que **múltiples servicios comparten infraestructura**
    
- Ayuda a los pentesters a identificar relaciones entre dominios aparentemente separados
    

---

## ✅ Resumen

- 🔐 Un certificado SSL puede usarse en varios puertos/servicios
    
- 🧾 SAN permite incluir muchos dominios en un solo certificado
    
- 🌐 Muy común en gobiernos, empresas grandes o servicios cloud

[[glosario]]

