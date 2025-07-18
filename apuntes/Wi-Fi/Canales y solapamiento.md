### 🔹 **Canales y solapamiento en redes Wi-Fi**

---

### 📡 ¿Qué es un canal en Wi-Fi?

Un **canal** es una subdivisión del espectro de frecuencia que se utiliza para transmitir datos inalámbricamente. En lugar de que todos los dispositivos usen la misma frecuencia exacta, se asignan **canales**, que son bandas más pequeñas dentro de la banda general de 2.4 GHz o 5 GHz.

---

### 🔁 Canales en la banda de **2.4 GHz**

- Esta banda va aproximadamente de **2.400 MHz a 2.483,5 MHz**.
    
- Hay **14 canales** posibles, aunque no todos están disponibles en todos los países:
    
    - En América se usan típicamente los canales **1 al 11**.
        
    - Cada canal ocupa **22 MHz**, pero están **separados solo por 5 MHz**, lo que genera **solapamiento**.
        

#### 📉 Solapamiento en 2.4 GHz

- Como los canales se solapan, si dos routers están en canales **cercanos**, generan **interferencia**, ruido, colisiones y caída de rendimiento.
    
- Por eso, solo se usan **3 canales no solapados**:
    
    - **Canal 1 (2412 MHz)**
        
    - **Canal 6 (2437 MHz)**
        
    - **Canal 11 (2462 MHz)**
        

#### 📘 Ejemplo visual de solapamiento:

```
Canal 1:     [-----]
Canal 2:        [-----]
Canal 3:           [-----]
Canal 6:                    [-----]
Canal 11:                              [-----]
```

---

### ⚡ Canales en la banda de **5 GHz**

- Esta banda va de **5.150 MHz a 5.825 MHz**.
    
- Los canales están separados por **20 MHz o más**, lo que reduce el solapamiento.
    
- Hay **23 canales no solapados** en muchos países, aunque algunos requieren DFS (Dynamic Frequency Selection) por posible interferencia con radares.
    
- También existen anchos de canal mayores:
    
    - **20 MHz (estándar)**
        
    - **40 MHz**
        
    - **80 MHz**
        
    - **160 MHz** (para redes muy rápidas, pero sensibles a interferencias)
        

---

### 🆚 Comparación rápida

|Característica|2.4 GHz|5 GHz|
|---|---|---|
|Rango|Mayor (más alcance)|Menor (más sensible)|
|Velocidad|Menor|Mayor|
|Interferencia|Alta (por solapamiento)|Baja|
|Canales no solapados|3|20+|
|Uso común|Hogares, IoT|Oficinas, streaming, gaming|

---

### 🔐 ¿Por qué importa esto para un red teamer?

- Entender los canales te permite:
    
    - **Escanear** mejor el espectro (usando herramientas como `airodump-ng`, `kismet`, `horst`, etc.)
        
    - **Evitar colisiones** si levantas un rogue AP
        
    - **Optimizar ataques de deautenticación** sin afectar canales vecinos
        
    - **Detectar objetivos en canales solapados** (ataques menos obvios)
        



---

[[index-wifi_security]]