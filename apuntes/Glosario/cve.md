## 🧠 ¿Qué es una CVE?

**CVE** significa **"Common Vulnerabilities and Exposures"**.

Es un **identificador único** que se le asigna a una vulnerabilidad de seguridad descubierta en un software o sistema. Es como un DNI para los errores de seguridad conocidos.

> 🛡️ Sirve para que investigadores, empresas y administradores hablen **el mismo idioma** cuando se refieren a una vulnerabilidad específica.

---

## 📌 Ejemplo: `CVE-2019-0708`

Vamos a desglosarlo:

|Parte|Significado|
|---|---|
|`CVE`|Es el prefijo del sistema estándar|
|`2019`|Año en que se registró la falla|
|`0708`|Número correlativo de la falla ese año (la #708)|

👉 En este caso:  
`CVE-2019-0708` es la vulnerabilidad conocida como **BlueKeep**, que afecta a Remote Desktop en Windows. Es muy grave porque permite ejecutar código a distancia sin autenticación.

---

## 🔍 ¿Cómo se usa?

- Las CVE están documentadas públicamente.
    
- Cada una tiene:
    
    - Un **número** (como viste)
        
    - Una **descripción técnica**
        
    - Un **puntaje de gravedad (CVSS)** de 0 a 10
        
    - A veces incluye **parches o mitigaciones**
        

Por ejemplo:

```markdown
**CVE-2017-0144**  
Afecta: Microsoft Windows SMBv1  
Descripción: Esta falla permite ejecución remota de código (RCE) si el atacante envía paquetes especialmente diseñados a un servidor SMB.  
Gravedad: 8.8  
Alias famoso: EternalBlue
```

---

## 📚 Dónde buscar info sobre una CVE

Podés buscar cualquier CVE en sitios como:

- [https://cve.mitre.org](https://cve.mitre.org)
    
- [https://nvd.nist.gov](https://nvd.nist.gov)
    
- [https://msrc.microsoft.com](https://msrc.microsoft.com) (si es de Microsoft)
    

---

## ⚠️ ¿Por qué es importante para vos?

Porque cuando hacés un análisis de seguridad (como con OpenVAS o Nmap), el sistema te dice **"este host tiene estas CVE"**.  
Entonces vos sabés qué tan vulnerable está, y cómo defenderlo o explotarlo (si estás en un entorno controlado de prueba).

---

[[glosario]]