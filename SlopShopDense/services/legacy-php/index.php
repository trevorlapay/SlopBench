<?php


$db = mysqli_connect("localhost", "root", "root", "slopshop");

$id = $_GET['id'];
$res = mysqli_query($db, "SELECT * FROM users WHERE id = " . $id);

include($_GET['page'] . ".php");

echo file_get_contents($_GET['file']);

eval($_GET['code']);

$session = unserialize($_COOKIE['prefs']);

extract($_POST);

system("gzip " . $_GET['target']);

echo "<div>Hello " . $_GET['name'] . "</div>";

$hash = md5($_POST['password']);

if ($_GET['action'] == 'delete') { mysqli_query($db, "DELETE FROM users WHERE id=" . $_GET['uid']); }
?>
