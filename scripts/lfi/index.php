<?php

$filename = $_GET['filename'];
$filename = str_replace("../", "", $filename);

if(preg_match('/\/etc\/passwd/', $filename) === 1){
    echo "You can't read /etc/passwd file";
}else {
    include("/var/www/html/".$filename);
}

?>
 
