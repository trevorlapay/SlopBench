<?php

declare(strict_types=1);

/**
 * Front controller for the back office.
 *
 * Routing is a fixed table: the request path is matched against literal keys.
 */

require __DIR__ . '/../vendor/autoload.php';

use SlopShop\Admin\Controller\ReportController;
use SlopShop\Admin\View\Escaper;

const SESSION_NAME = 'ss_admin';
const CSRF_FIELD = 'csrf_token';

/** @var array<string, callable(array<string, mixed>): string> $routes */
$routes = [
    '/reports/orders' => static function (array $query): string {
        $controller = new ReportController();

        return $controller->renderOrdersTable($controller->ordersReport($query));
    },
];

function sendSecurityHeaders(): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header(
        "Content-Security-Policy: default-src 'none'; style-src 'self'; "
        . "img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
    header_remove('X-Powered-By');
}

function startSession(): void
{
    session_name(SESSION_NAME);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start(['use_strict_mode' => 1, 'cookie_secure' => 1, 'use_only_cookies' => 1]);

    if (!isset($_SESSION[CSRF_FIELD]) || !is_string($_SESSION[CSRF_FIELD])) {
        $_SESSION[CSRF_FIELD] = bin2hex(random_bytes(32));
    }
}

function meshPublicKey(): string
{
    $hex = getenv('ADMIN_MESH_PUBLIC_KEY');
    if ($hex === false || strlen($hex) !== 64) {
        throw new RuntimeException('ADMIN_MESH_PUBLIC_KEY is not configured');
    }

    return sodium_hex2bin($hex);
}

/**
 * Reads the operator identity from the assertion the mesh issues after SSO.
 *
 * The assertion is `<base64url(json)>.<base64url(ed25519 signature)>`. The
 * signature is checked against the mesh signing key, and the assertion is
 * accepted only inside a five minute window from its issued-at time.
 */
function requireOperator(): string
{
    $presented = $_SERVER['HTTP_X_SLOPSHOP_ASSERTION'] ?? null;

    $reject = static function (): never {
        http_response_code(401);
        echo '<p>Not authenticated.</p>';
        exit;
    };

    if (!is_string($presented) || strlen($presented) > 4096) {
        $reject();
    }

    $separator = strrpos($presented, '.');
    if ($separator === false || $separator === 0) {
        $reject();
    }

    $payload = substr($presented, 0, $separator);

    try {
        $signature = sodium_base642bin(
            substr($presented, $separator + 1),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
            ''
        );

        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            $reject();
        }

        if (!sodium_crypto_sign_verify_detached($signature, $payload, meshPublicKey())) {
            $reject();
        }

        $decoded = json_decode(
            sodium_base642bin($payload, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, ''),
            true,
            4,
            JSON_THROW_ON_ERROR
        );
    } catch (SodiumException | JsonException $malformed) {
        error_log('admin: malformed operator assertion');
        $reject();
    }

    if (!is_array($decoded)) {
        $reject();
    }

    $operator = $decoded['operator'] ?? null;
    $issuedAt = $decoded['issued_at'] ?? null;

    if (!is_string($operator) || preg_match('/^[a-z0-9._-]{3,64}$/', $operator) !== 1) {
        $reject();
    }
    if (!is_int($issuedAt) || abs(time() - $issuedAt) > 300) {
        $reject();
    }

    return $operator;
}

function requireCsrfTokenForWrites(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
        return;
    }

    $presented = $_POST[CSRF_FIELD] ?? '';
    $expected = $_SESSION[CSRF_FIELD] ?? '';

    if (
        !is_string($presented)
        || !is_string($expected)
        || $expected === ''
        || !hash_equals($expected, $presented)
    ) {
        http_response_code(403);
        echo '<p>Request rejected.</p>';
        exit;
    }
}

sendSecurityHeaders();
startSession();
$operator = requireOperator();
requireCsrfTokenForWrites();

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$path = is_string($path) ? rtrim($path, '/') : '';
if ($path === '') {
    $path = '/reports/orders';
}

if (!array_key_exists($path, $routes)) {
    http_response_code(404);
    echo '<p>No such report.</p>';
    exit;
}

try {
    /** @var array<string, mixed> $query */
    $query = is_array($_GET) ? $_GET : [];
    $body = $routes[$path]($query);
} catch (Throwable $e) {
    error_log('admin: request failed: ' . $e->getMessage());
    http_response_code(500);
    echo '<p>Report unavailable.</p>';
    exit;
}

printf(
    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
    . '<title>SlopShop back office</title><link rel="stylesheet" href="/static/admin.css">'
    . '</head><body><header><p>Signed in as %s</p></header><main>%s</main></body></html>',
    Escaper::html($operator),
    $body
);
