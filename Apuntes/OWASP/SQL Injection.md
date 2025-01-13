
# SQL Injection (SQLI)

## ¿Qué es una inyección SQL?  
Una **inyección SQL** es una técnica de ataque que aprovecha vulnerabilidades en aplicaciones web que no validan correctamente la entrada del usuario. Los atacantes pueden insertar **código SQL malicioso** en campos de entrada para:  
- Obtener información confidencial (usuarios, contraseñas, etc.).  
- Controlar o manipular la base de datos.  

## ¿Cómo ocurre?  
Las inyecciones SQL ocurren cuando una aplicación permite que código malicioso ingresado por un atacante sea procesado como parte de una consulta SQL hacia la base de datos.

---

## Tipos de Inyecciones SQL  

1. **Basada en errores**:  
   Utiliza mensajes de error para revelar información sobre la base de datos.  
Ejemplos
- Obtener las base de datos que corren en el sistema
> ?id=12232' union select group_concat(schema_name) from information_schema.schemata-- -

- Obtener las **tablas** de una base de datos dada
> ?id=12232' union select group_concat(table_name) from information_schema.tables where table_schema='hack'-- -

- Obtener las **columnas** de una base de datos y una tabla dada
> ?id=12232' union select group_concat(column_name) from information_schema.columns where table_schema='hack' and table_name='users'-- -


1. **Basada en tiempo**:  
   Ejecuta consultas que generan un retraso, permitiendo deducir información según el tiempo de respuesta.  
   
> ?id=1' and sleep(3)-- ojo que debe ser un id valido tambien

2. **Basada en booleanos** *(boolean based blind injections)*:
   Usa expresiones booleanas para obtener respuestas sí/no y deducir información. **ideal para cuando se va a ciegas (url sanitizada o no se muestra informacion etc.)** 
- Ejemplo
> select(select ascii(substring(firstname,1,1)) from scientist where id=1)=97;
> devuelve 1 o 0 dependiendo si es verdadero o falso respectivamente.


3. **Basada en uniones (UNION)**:  
   Combina múltiples consultas con `UNION` para acceder a datos adicionales.  

4. **Basada en consultas apiladas (stacked queries)**:  
   Permite ejecutar varias consultas en una sola instrucción para obtener datos adicionales o manipular la base.  

---

## Bases de Datos Vulnerables  

- **Relacionales** (MySQL, PostgreSQL, SQL Server): Las más afectadas debido al uso intensivo de SQL.  
- **NoSQL** (MongoDB, Cassandra): Vulnerables a inyecciones de comandos.  
- **De grafos** (Neo4j): Sus consultas también pueden ser explotadas.  
- **De objetos** (db4o): Explotables mediante la manipulación de consultas específicas.  

---

## ¿Cómo prevenir inyecciones SQL?  
- **Validar y sanitizar entradas del usuario**.  
- **Usar consultas preparadas (prepared statements)**.  
- **Evitar concatenar cadenas en consultas SQL**.  

---

## Recurso adicional  
- **MySQL Online (ExtendsClass)**: [https://extendsclass.com/mysql-online.html](https://extendsclass.com/mysql-online.html)  


---
[[OWASP]]