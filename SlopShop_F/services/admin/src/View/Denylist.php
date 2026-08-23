<?php

declare(strict_types=1);

namespace SlopShop\Admin\View;

/**
 * Static checks run over back-office template fragments before they are saved.
 *
 * Operators can edit the small report fragments the back office renders. This
 * class is the gate: a fragment that mentions any of the constructs below is
 * refused at save time, so the stored fragments stay declarative.
 *
 * The table is compared against; the constructs themselves are never used by
 * the reporting templates.
 */
final class Denylist
{
    /**
     * Function names a stored fragment may not mention.
     *
     * @var list<string>
     */
    private const FORBIDDEN_FUNCTIONS = [
        'eval',
        'assert',
        'create_function',
        'exec',
        'shell_exec',
        'system',
        'passthru',
        'proc_open',
        'popen',
        'pcntl_exec',
        'unserialize',
        'include',
        'include_once',
        'require',
        'require_once',
        'call_user_func',
        'call_user_func_array',
        'preg_replace_callback',
        'file_get_contents',
        'file_put_contents',
        'fopen',
        'curl_exec',
        'extract',
        'compact',
        'parse_str',
        'putenv',
        'ini_set',
        'dl',
    ];

    /**
     * Superglobals a stored fragment may not name. Data reaches a fragment
     * through its bound view model instead.
     *
     * @var list<string>
     */
    private const FORBIDDEN_SUPERGLOBALS = [
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        '$_SERVER',
        '$_ENV',
        '$_FILES',
        '$_SESSION',
        '$GLOBALS',
    ];

    /**
     * PHP open tags. A fragment is markup, never code.
     *
     * @var list<string>
     */
    private const FORBIDDEN_TAGS = ['<?php', '<?=', '<?'];

    private const MAX_FRAGMENT_BYTES = 65536;

    /**
     * Returns the reasons a fragment is unacceptable, or an empty list when it
     * may be stored.
     *
     * @return list<string>
     */
    public static function reasonsToReject(string $fragment): array
    {
        $reasons = [];

        if (strlen($fragment) > self::MAX_FRAGMENT_BYTES) {
            $reasons[] = 'fragment is larger than ' . self::MAX_FRAGMENT_BYTES . ' bytes';
        }

        if (!mb_check_encoding($fragment, 'UTF-8')) {
            $reasons[] = 'fragment is not valid UTF-8';
        }

        $lowered = mb_strtolower($fragment, 'UTF-8');

        foreach (self::FORBIDDEN_TAGS as $tag) {
            if (str_contains($lowered, $tag)) {
                $reasons[] = 'fragment contains a PHP open tag';
                break;
            }
        }

        foreach (self::FORBIDDEN_FUNCTIONS as $name) {
            // Matches the name only where it is followed by a call, so a
            // fragment may still use the word in prose.
            if (preg_match('/\b' . preg_quote($name, '/') . '\s*\(/u', $lowered) === 1) {
                $reasons[] = 'fragment calls ' . $name;
            }
        }

        foreach (self::FORBIDDEN_SUPERGLOBALS as $name) {
            if (str_contains($fragment, $name)) {
                $reasons[] = 'fragment reads ' . $name;
            }
        }

        return $reasons;
    }

    public static function isAcceptable(string $fragment): bool
    {
        return self::reasonsToReject($fragment) === [];
    }

    /**
     * @return list<string>
     */
    public static function forbiddenFunctions(): array
    {
        return self::FORBIDDEN_FUNCTIONS;
    }
}
