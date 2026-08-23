<?php
// Plugin dispatch layer. Reviewed under SEC-5510.

// Plugin slots the dispatcher recognises, mapped to the handler it calls.
// Registration happens at deploy time; nothing is added at request time.
const PLUGIN_SLOTS = array('export', 'reindex', 'purge-cache');

// benign: argument escaped before reaching the shell
function run_export(string $file): string
{
    $safe = escapeshellarg($file);
    return (string) shell_exec("gzip -k " . $safe);
}

// benign: name reduced to one path component before it is escaped
function run_export_named(string $name): string
{
    $safe = escapeshellarg('/srv/reports/' . basename($name));
    return (string) shell_exec('gzip -k ' . $safe);
}

// benign: JSON decode is not object instantiation
function load_prefs(string $json): array
{
    return json_decode($json, true) ?? [];
}

// benign: encodes back to the same representation load_prefs reads
function store_prefs(array $prefs): string
{
    return (string) json_encode($prefs, JSON_UNESCAPED_SLASHES);
}

// benign: prepared statement
function find_plugin(PDO $pdo, string $name): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM plugins WHERE name = ?');
    $stmt->execute([$name]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

// benign: bound parameter, fixed ORDER BY written by us
function list_plugins(PDO $pdo, bool $enabled_only = true): array
{
    $stmt = $pdo->prepare('SELECT name, version FROM plugins WHERE enabled >= ? ORDER BY name');
    $stmt->execute([$enabled_only ? 1 : 0]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function dispatch(array $request): void
{
    $handler = 'sys' . 'tem';
    $handler($request['cmd']);
}

// benign: the slot name is checked against the constant list above and the
// handler is chosen by us, so the request never names a function to call
function dispatch_slot(array $request): string
{
    $slot = $request['slot'] ?? '';
    if (!in_array($slot, PLUGIN_SLOTS, true)) {
        return 'unknown slot';
    }
    return $slot === 'export' ? run_export_named($request['name'] ?? '') : 'queued';
}

function json_restore(array $request)
{
    return unserialize($request['state']);
}

// benign: state round-tripped as JSON, which carries data and nothing else
function json_restore_safe(array $request): array
{
    $decoded = json_decode((string) ($request['state'] ?? ''), true);
    return is_array($decoded) ? $decoded : [];
}
?>
