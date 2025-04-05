### **Explotación de Vulnerabilidades**

Es el proceso de aprovechar fallas en sistemas, aplicaciones o redes para acceder a datos o ejecutar acciones no autorizadas. Estas fallas pueden ser errores de configuración, bugs en el software o malas prácticas de seguridad.

---

### **Tipos de explotación**

#### **1. Explotación Manual**

En este enfoque, un atacante identifica y explota vulnerabilidades de forma directa, ajustando cada paso según las respuestas del sistema.  
🔑 **Ejemplo sencillo**:

- Encontrar un formulario web sin validación.
- Inyectar código malicioso manualmente, como:

```sql
' OR '1'='1' --     
```

en un campo de login para realizar un ataque de **SQL Injection**.

#### **Ventajas**:

- Alta personalización según el objetivo.
- Ideal para casos donde las herramientas automáticas no funcionan.

#### **Desventajas**:

- Requiere más tiempo y conocimientos técnicos.

---

#### **2. Explotación Automatizada**

Aquí, se usan herramientas para buscar y explotar vulnerabilidades automáticamente. Esto es más rápido y eficiente para ataques en gran escala.

🔧 **Ejemplo sencillo**:

- Usar **wpscan** para buscar vulnerabilidades en un sitio WordPress:

```bash
wpscan --url http://example.com --enumerate vp
```

- Utilizar **Metasploit** para ejecutar un exploit conocido contra un sistema vulnerable:

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.1.100
exploit
```


#### **Ventajas**:

- Rápido y eficiente.
- Detecta múltiples fallas en poco tiempo.

#### **Desventajas**:

- Menor control sobre el proceso.
- Puede generar ruido, alertando al objetivo.

---

### **Comparación entre manual y automatizada**

|**Aspecto**|**Manual**|**Automatizada**|
|---|---|---|
|**Velocidad**|Lento|Rápido|
|**Precisión**|Alta (depende del atacante)|Media (pueden ocurrir falsos positivos)|
|**Conocimiento**|Requiere experiencia|Básico (gracias a las herramientas)|
|**Casos de uso**|Sistemas únicos, específicos|Reconocimientos masivos o tests rápidos|

---

### **Herramientas comunes para cada enfoque**

#### **Manual**:

- **Burp Suite**: Análisis de tráfico HTTP y explotación de fallas web.
- **SQLmap (semi-automático)**: Puede usarse manualmente para inyecciones SQL específicas.
- **nmap + scripts NSE**: Escaneo manualmente ajustado con scripts personalizados.

#### **Automatizada**:

- **Metasploit Framework**: Exploit multiuso automatizado.
- **WPScan**: Ataques automáticos en WordPress.
- **Nikto**: Identificación automática de vulnerabilidades en servidores web.

---

### **Conclusión**

- La explotación manual es para casos específicos donde el detalle importa.
- La automatización es ideal para escaneos masivos o pruebas rápidas.  
    Aprender ambos enfoques te hace más versátil, ya sea para pruebas de penetración **(Ethical Hacking)** o para defender sistemas. 🚀

[[Enumeracion y Explotacion]]