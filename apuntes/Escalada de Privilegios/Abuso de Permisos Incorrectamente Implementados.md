---
Tema: "[[Escalada de Privilegios]]"
---

---
Practica
puede pasar que cuando se quiera escalar privilegios es importante mirar los permisos con los que cuentan cada archivo. al menos de los importantes. por ejemplo este caso

el etc passwd tiene permisos de otros con escritura o+w

explicar que es el etc passwd y el etc shadow.

cuando uno debe autenticarse con la contraseña generalmente lo valida por el etc shadow pero si harcodeas la contraseña hasheada en el etc passwd es posible que no la valide con el etc shadow ya que se encuentra en el passwd.

aqui entra el problema


