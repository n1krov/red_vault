
> Eso se refiere a una **configuración vulnerable en versiones antiguas de Windows** que **no tienen parches de seguridad aplicados** y, **clave para exploits como BlueKeep**, **no tienen habilitado NLA (Network Level Authentication)**.

### 🔒 ¿Qué es NLA?

**NLA (Network Level Authentication)** es una *capa de seguridad* para **RDP** (Remote Desktop Protocol) que **exige autenticación antes de establecer la sesión**.

- Si **NLA está habilitado**, **no podés explotar BlueKeep** directamente sin credenciales.
    
- Si **NLA está deshabilitado**, **el sistema es vulnerable** (si también no tiene parches).
    

---

### 📌 Entonces, ¿qué significa esa frase?

> **"Windows sin parchear (pre-Windows 10 y sin NLA habilitado)"**  
> Esto describe **una víctima ideal para BlueKeep**:

|Requisito|Estado esperado|
|---|---|
|Sistema Operativo|Windows 7, Server 2008 o similares|
|Parche de seguridad|No aplicado|
|NLA|**Desactivado**|

En ese escenario, **el exploit de BlueKeep puede ejecutar código remotamente sin autenticación**, lo que te da acceso directo a una shell o sesión.

---

### ✅ ¿Cómo saber si NLA está habilitado?

Podés usar `nmap` con un script NSE:

```bash
nmap -p 3389 --script rdp-enum-encryption 10.2.0.15
```

Si ves algo como:

```
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): not supported
```

→ **No tiene NLA** → **Explotable con BlueKeep**.

---
[[glosario]]