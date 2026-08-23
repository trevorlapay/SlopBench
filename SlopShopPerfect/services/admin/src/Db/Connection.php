<?php

declare(strict_types=1);

namespace SlopShop\Admin\Db;

use PDO;
use PDOException;
use RuntimeException;

/**
 * The back office's read-only database handle.
 *
 * Credentials come from the environment. The role the back office connects as
 * has SELECT rights only.
 */
final class Connection
{
    private static ?PDO $instance = null;

    private function __construct()
    {
    }

    public static function get(): PDO
    {
        if (self::$instance instanceof PDO) {
            return self::$instance;
        }

        $dsn = self::requiredEnv('ADMIN_DATABASE_DSN');
        $user = self::requiredEnv('ADMIN_DATABASE_USER');
        $password = self::requiredEnv('ADMIN_DATABASE_PASSWORD');

        try {
            $pdo = new PDO($dsn, $user, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_STRINGIFY_FETCHES => false,
                PDO::ATTR_PERSISTENT => false,
            ]);
        } catch (PDOException $e) {
            // The driver message can carry the DSN; it goes to the log only.
            error_log('admin: database connection failed: ' . $e->getMessage());
            throw new RuntimeException('database unavailable');
        }

        // The back office is a reader.
        $pdo->exec('SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY');
        $pdo->exec("SET statement_timeout = '15s'");

        self::$instance = $pdo;

        return $pdo;
    }

    private static function requiredEnv(string $name): string
    {
        $value = getenv($name);
        if ($value === false || $value === '') {
            throw new RuntimeException('missing required environment variable: ' . $name);
        }

        return $value;
    }
}
