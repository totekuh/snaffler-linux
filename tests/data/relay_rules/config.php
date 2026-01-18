<?php
$db_host = "localhost";
$db_user = "root";
$db_pass = "mysql_password123";
$db_name = "webapp_db";

$conn = mysql_connect($db_host, $db_user, $db_pass);
if (!$conn) {
    die("Connection failed");
}
?>
