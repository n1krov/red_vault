<?php
// Habilitar la visualización de errores
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


$server="localhost";
$username="lautaro";
$password="esqwer";
$database="hack";

$connect=new mysqli($server, $username, $password, $database);

// sanitizacion
$res= mysqli_real_escape_string($connect, $_GET['id']);
/* $res=$_GET['id']; */

echo "Valor introducido  --> " . $res . "<br> ----------------- <br>";

$data= mysqli_query($connect, "select username from users where id=$res") or die(mysqli_error($connect));

$response= mysqli_fetch_array($data);

/* echo $response['username']; */

if (! isset($response['username'])){
    http_response_code(404);
}

?>
