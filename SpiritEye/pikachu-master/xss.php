<?php

if ($_SERVER['REQUEST_METHOD'] == 'HEAD') {
    header("Content-Type: image/png");
    exit;
}

header("Location: https://kabuqin.github.io/cappuccino.github.io/1.svg");

?>