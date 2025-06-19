### ¿Por qué usamos `reverse_tcp`?

Porque la mayoría de los firewalls **bloquean conexiones entrantes**, pero **permiten salientes**. Entonces:

1. Vos abrís un puerto en tu máquina (ej: `4444`).
    
2. Cuando el exploit tiene éxito, la víctima **se conecta a tu IP y puerto**.
    
3. Ahí recibís una sesión de `meterpreter`.
    



---
[[glosario]]