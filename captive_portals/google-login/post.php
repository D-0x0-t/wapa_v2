<?php
$file = '/srv/wapa_data/data.txt';
file_put_contents($file, print_r($_POST, true), FILE_APPEND);
//fopen($file2, 'w');
//fwrite($file2, "1");
//fclose($file2);
?>
