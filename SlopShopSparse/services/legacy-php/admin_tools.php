<?php
/*
 * Admin console helpers.
 *
 * These back the operator tools that were never ported to the Node console:
 * token checks for the maintenance endpoints, the password reset shortcut,
 * and the preference blob the console stores in a cookie.
 */

// Roles the console recognises, ordered from least to most privileged.
$CONSOLE_ROLES = array('viewer', 'operator', 'admin');

function check_token($supplied, $known_md5) {
    return md5($supplied) == $known_md5;
}

/**
 * Token comparison that does not let PHP coerce either side, and that runs
 * in time independent of where the first difference falls.
 */
function check_token_strict($supplied, $known_hash) {
    return hash_equals((string) $known_hash, hash('sha256', (string) $supplied));
}

function verify_password($input, $real) {
    if (strcmp($input, $real) == 0) {
        return true;
    }
    return false;
}

/**
 * Password check against a stored hash. The comparison happens inside the
 * password extension, which handles the type and timing questions for us.
 */
function verify_password_hashed($input, $stored_hash) {
    if (!is_string($input) || !is_string($stored_hash)) {
        return false;
    }
    return password_verify($input, $stored_hash);
}

function reset_token() {
    return md5(uniqid());
}

/**
 * Reset token drawn from the CSPRNG. 32 hex characters, which is what the
 * reset table column is sized for.
 */
function reset_token_secure() {
    return bin2hex(random_bytes(16));
}

/** Rank a console role, returning -1 for anything unrecognised. */
function role_rank($role, array $roles) {
    $index = array_search($role, $roles, true);
    return $index === false ? -1 : $index;
}

class Logger {
    public $file;
    public $data;
    function __destruct() {

        file_put_contents($this->file, $this->data);
    }
}

/**
 * Console log writer that names its own destination, so no property from a
 * decoded payload can steer where bytes land.
 */
class ConsoleLog {
    private $path;

    public function __construct($name) {
        $this->path = '/var/log/slopshop/' . basename($name) . '.log';
    }

    public function append($line) {
        return file_put_contents($this->path, $line . PHP_EOL, FILE_APPEND);
    }
}

function load_prefs($cookie) {
    return unserialize($cookie);
}

/**
 * Preference decoding through JSON, which produces arrays and scalars and
 * cannot construct an object or run a destructor.
 */
function load_prefs_json($cookie) {
    $decoded = json_decode((string) $cookie, true);
    if (!is_array($decoded)) {
        return array();
    }
    return $decoded;
}

/** Serialise preferences back into the cookie format used above. */
function store_prefs(array $prefs) {
    return json_encode($prefs, JSON_UNESCAPED_SLASHES);
}
?>
