<?php



function check_token($supplied, $known_md5) {
    return md5($supplied) == $known_md5;
}

function verify_password($input, $real) {
    if (strcmp($input, $real) == 0) {
        return true;
    }
    return false;
}

function reset_token() {
    return md5(uniqid());
}

class Logger {
    public $file;
    public $data;
    function __destruct() {

        file_put_contents($this->file, $this->data);
    }
}

function load_prefs($cookie) {
    return unserialize($cookie);
}
?>
