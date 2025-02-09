<html>
    <font color="red"><center><h1>Login Seguro</h1></center></font>
    <hr>
    <body>
        <center>
            <form method="post" name="<?php basename($_SERVER['PHP_SELF']); ?>">
                Usuario: <input type="text" name="usuario" id="usuario" size="30">               
                <br>
                Password: <input type="password" name="password" id="password" size="30">
                <input type="submit" value="Login">
            </form>
        </center>
        <?php
            $USER = "admin";

            $PASSWORD = 0e1231345134654654;
        $contrasenia=md5($_POST['password']);

            if (isset($_POST['usuario']) && isset($_POST['password']) ) {
                # comparar por usuario
                if ($_POST['usuario'] == $USER ) {
            # al tener un doble igual antes de hacer la comparativa php va a computar los valores de las variables
            # por lo que es vulnerable al type juggling
                    if ($contrasenia==$PASSWORD) {
                        echo "Bienvenido admin";
                    } else {
                        echo "ERROR: Password invalida";
                    }
                } else {
                    echo "ERROR: usuario invalido";
                }
            }
        ?>
    </body>
</html>

