<?php

declare(strict_types=1);

/**
 * 1Password CLI integration for Compose Manager.
 *
 * Detection reads the files a stack's compose command consumes (the env file
 * used for interpolation and every compose file) and looks for `op://`
 * secret references. It never resolves a reference, never runs
 * `docker compose config`, and never runs the 1Password CLI, so it is cheap
 * enough for every stack-list refresh and works while 1Password is locked.
 *
 * Status reports whether the 1Password CLI helpers are installed and whether
 * the RAM-only service-account token is currently loaded. The token is never
 * read: only its presence is checked.
 *
 * This file is dependency-free so shell helpers can load it on its own.
 */

defined('COMPOSE_OP_SECURE_BIN') || define('COMPOSE_OP_SECURE_BIN', '/usr/local/bin/op-secure');
defined('COMPOSE_OP_STATUS_BIN') || define('COMPOSE_OP_STATUS_BIN', '/usr/local/bin/op-status');
defined('COMPOSE_OP_TOKEN_FILE') || define('COMPOSE_OP_TOKEN_FILE', '/run/1password/service-account-token');
defined('COMPOSE_OP_STATUS_CACHE_FILE') || define('COMPOSE_OP_STATUS_CACHE_FILE', '/var/tmp/compose-manager-onepassword-status.json');

/**
 * Result of scanning one stack's effective configuration for `op://` references.
 *
 * Holds variable names, file paths and reasons only. Reference values are
 * never kept, so a detection can be rendered or logged as-is.
 */
final class OnePasswordDetection
{
    /** @var bool Whether any `op://` reference was found anywhere in the effective config */
    public bool $uses = false;

    /** @var string|null Env file used for interpolation that holds references (the supported pattern) */
    public ?string $envFile = null;

    /** @var string[] Variable names in $envFile whose value is a 1Password reference */
    public array $envKeys = [];

    /** @var string[] Variable names in $envFile whose `op://` value is not a valid reference */
    public array $invalidKeys = [];

    /** @var string[] Reasons the configuration cannot be deployed with resolved secrets */
    public array $unsupported = [];

    /** @var string[] Files that exist but could not be read during the scan */
    public array $unreadable = [];

    /**
     * Whether up/update may proceed once 1Password is unlocked.
     */
    public function isDeployable(): bool
    {
        return $this->uses
            && $this->envFile !== null
            && $this->invalidKeys === []
            && $this->unsupported === [];
    }

    /**
     * A message explaining why deployment is blocked by the configuration
     * itself (independent of the lock state), or null when it is not.
     */
    public function getBlockReason(): ?string
    {
        if (!$this->uses) {
            return null;
        }
        $reasons = [];
        if ($this->invalidKeys !== []) {
            $reasons[] = 'Invalid 1Password reference syntax for: ' . implode(', ', $this->invalidKeys)
                . '. Expected op://<vault>/<item>/[<section>/]<field>.';
        }
        foreach ($this->unsupported as $reason) {
            $reasons[] = $reason;
        }
        if ($reasons === [] && $this->envFile === null) {
            $reasons[] = 'No project env file with 1Password references was found.';
        }
        return $reasons === [] ? null : implode(' ', $reasons);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'uses' => $this->uses,
            'deployable' => $this->isDeployable(),
            'envFile' => $this->envFile,
            'envKeys' => $this->envKeys,
            'invalidKeys' => $this->invalidKeys,
            'unsupported' => $this->unsupported,
            'blockReason' => $this->getBlockReason(),
        ];
    }
}

final class OnePassword
{
    public const STATE_UNLOCKED = 'unlocked';
    public const STATE_LOCKED = 'locked';
    public const STATE_UNAVAILABLE = 'unavailable';
    public const STATE_ERROR = 'error';

    public const INDICATOR_TOOLTIP = 'Uses 1Password-managed environment secrets';

    public const LOCKED_MESSAGE = 'This project uses 1Password secrets. Unlock 1Password on Unraid using op-unlock before deploying.';
    public const UNAVAILABLE_MESSAGE = 'This project uses 1Password secrets, but the 1Password CLI helpers were not found. Install the 1Password CLI and the op-secure helper (/usr/local/bin/op-secure) on Unraid, then run op-unlock before deploying.';
    public const NOT_ENABLED_MESSAGE = 'This project uses 1Password secrets, and resolving them on deploy is turned off (Settings > Resolve 1Password Secrets on Deploy). The action was blocked so unresolved op:// references are never passed to containers. Running containers were not changed.';
    public const ERROR_MESSAGE ='This project uses 1Password secrets, but the 1Password status check failed. Run op-status on Unraid, then op-unlock if needed, before deploying.';

    /** How long a status result from op-status is reused, in seconds */
    private const STATUS_CACHE_TTL = 60;

    /** @var array<string, string> Path overrides for tests */
    private static array $paths = [];

    /** @var callable|null Runs a status command and returns its exit code (tests replace it) */
    private static $statusRunner = null;

    /** @var array<string, OnePasswordDetection> Per-request detection cache keyed by inputs */
    private static array $detections = [];

    /**
     * Override binary/token/cache paths (tests only).
     *
     * @param array<string, string> $paths Keys: opSecure, opStatus, tokenFile, cacheFile
     */
    public static function configure(array $paths, ?callable $statusRunner = null): void
    {
        self::$paths = $paths;
        self::$statusRunner = $statusRunner;
        self::$detections = [];
    }

    public static function opSecureBin(): string
    {
        return self::$paths['opSecure'] ?? COMPOSE_OP_SECURE_BIN;
    }

    public static function opStatusBin(): string
    {
        return self::$paths['opStatus'] ?? COMPOSE_OP_STATUS_BIN;
    }

    public static function tokenFile(): string
    {
        return self::$paths['tokenFile'] ?? COMPOSE_OP_TOKEN_FILE;
    }

    private static function statusCacheFile(): string
    {
        return self::$paths['cacheFile'] ?? COMPOSE_OP_STATUS_CACHE_FILE;
    }

    // ---------------------------------------------------------------
    // Detection
    // ---------------------------------------------------------------

    /**
     * Scan a stack's effective configuration for 1Password references.
     *
     * @param string[] $composeFiles Compose files the command uses, in -f order
     * @param string|null $envFile Env file used for interpolation (--env-file or the project .env)
     * @param string|null $projectDir Directory relative env_file paths resolve from
     */
    public static function scan(array $composeFiles, ?string $envFile, ?string $projectDir = null): OnePasswordDetection
    {
        $composeFiles = array_values(array_filter($composeFiles, static fn(string $f): bool => $f !== ''));
        $cacheKey = json_encode([$composeFiles, $envFile, $projectDir, self::mtimes(array_merge($composeFiles, [$envFile]))]);
        if (isset(self::$detections[$cacheKey])) {
            return self::$detections[$cacheKey];
        }

        $detection = new OnePasswordDetection();
        if ($projectDir === null || $projectDir === '') {
            $projectDir = $composeFiles !== [] ? dirname($composeFiles[0]) : ($envFile !== null ? dirname($envFile) : '');
        }

        // 1) The interpolation env file: the supported place for references.
        if ($envFile !== null && $envFile !== '' && is_file($envFile)) {
            $content = @file_get_contents($envFile);
            if ($content === false) {
                $detection->unreadable[] = $envFile;
            } else {
                $parsed = self::parseEnvReferences($content);
                if ($parsed['keys'] !== [] || $parsed['invalid'] !== []) {
                    $detection->uses = true;
                    $detection->envFile = $envFile;
                    $detection->envKeys = $parsed['keys'];
                    $detection->invalidKeys = $parsed['invalid'];
                    if ($parsed['interpolated'] !== []) {
                        $detection->unsupported[] = 'Env file ' . basename($envFile) . ' uses ${...} interpolation in '
                            . implode(', ', $parsed['interpolated'])
                            . '. Under op run those values are not expanded the way Docker Compose would expand them, so they could change. Use literal values in the 1Password-managed env file.';
                    }
                }
            }
        }

        // 2) Compose files: literal references and service-level env_file targets.
        $includesOtherFiles = false;
        $unresolvableEnvFile = false;
        $scannedEnvFiles = [];
        foreach ($composeFiles as $composeFile) {
            if (!is_file($composeFile)) {
                continue;
            }
            $yaml = @file_get_contents($composeFile);
            if ($yaml === false) {
                $detection->unreadable[] = $composeFile;
                continue;
            }

            if (self::yamlContainsReference($yaml)) {
                $detection->uses = true;
                $detection->unsupported[] = 'Compose file ' . basename($composeFile)
                    . ' contains a literal op:// reference. Containers would receive the reference text, not the secret.'
                    . ' Move the reference into the project env file and use ${VAR} in the compose file.';
            }

            if (self::yamlUsesIncludeOrExtendsFile($yaml)) {
                $includesOtherFiles = true;
            }

            $envFiles = self::extractServiceEnvFiles($yaml);
            if ($envFiles['unresolvable']) {
                $unresolvableEnvFile = true;
            }
            foreach ($envFiles['paths'] as $relative) {
                foreach (self::resolveServiceEnvFileCandidates($relative, $projectDir, dirname($composeFile)) as $candidate) {
                    $key = realpath($candidate) ?: $candidate;
                    if (isset($scannedEnvFiles[$key])) {
                        continue;
                    }
                    $scannedEnvFiles[$key] = true;
                    $content = @file_get_contents($candidate);
                    if ($content === false) {
                        $detection->unreadable[] = $candidate;
                        continue;
                    }
                    if (str_contains($content, 'op://')) {
                        $detection->uses = true;
                        $detection->unsupported[] = 'Service env_file ' . basename($candidate)
                            . ' contains op:// references. Compose passes env_file values to containers verbatim,'
                            . ' so they cannot be resolved safely. Reference the variables from the service'
                            . ' environment: section with ${VAR} instead.';
                    }
                }
            }
        }

        // Patterns the scanner cannot follow only matter for projects that use 1Password.
        if ($detection->uses && $includesOtherFiles) {
            $detection->unsupported[] = 'Compose include: or extends: file: directives are not audited for 1Password references.';
        }
        if ($detection->uses && $unresolvableEnvFile) {
            $detection->unsupported[] = 'A service env_file path could not be resolved without interpolation, so it cannot be checked for 1Password references.';
        }

        $detection->unsupported = array_values(array_unique($detection->unsupported));
        $detection->unreadable = array_values(array_unique($detection->unreadable));

        self::$detections[$cacheKey] = $detection;
        return $detection;
    }

    /**
     * Scan a plain stack directory when no StackInfo is available: the given
     * compose file, the override files Docker Compose would pick up next to
     * it, and the `.env` it loads by default.
     */
    public static function scanDirectory(string $dir, ?string $composeFile = null): OnePasswordDetection
    {
        $dir = rtrim($dir, '/');
        $files = [];
        if ($composeFile !== null && $composeFile !== '') {
            $files[] = $composeFile;
        }
        foreach (['compose.override.yaml', 'compose.override.yml', 'docker-compose.override.yaml', 'docker-compose.override.yml'] as $name) {
            if (is_file("$dir/$name")) {
                $files[] = "$dir/$name";
            }
        }
        $envFile = is_file("$dir/.env") ? "$dir/.env" : null;
        return self::scan($files, $envFile, $dir);
    }

    /**
     * Find variable names whose value is a 1Password reference.
     *
     * Follows the env-file rules Compose and `op run` share: `KEY=value`
     * lines, optional `export ` prefix, `#` comments, optional quotes.
     *
     * @return array{keys: string[], invalid: string[], interpolated: string[]}
     */
    public static function parseEnvReferences(string $content): array
    {
        $keys = [];
        $invalid = [];
        $interpolated = [];
        foreach (preg_split('/\R/', $content) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (str_starts_with($line, 'export ')) {
                $line = ltrim(substr($line, 7));
            }
            $eq = strpos($line, '=');
            if ($eq === false) {
                continue;
            }
            $key = trim(substr($line, 0, $eq));
            $rawValue = trim(substr($line, $eq + 1));
            $value = self::unquoteEnvValue($rawValue);
            if (!str_starts_with($rawValue, "'") && preg_match('/\$\{?[A-Za-z_]/', $value) === 1) {
                $interpolated[] = $key;
            }
            if (!str_contains($value, 'op://')) {
                continue;
            }
            if (self::isValidReference($value)) {
                $keys[] = $key;
            } else {
                $invalid[] = $key;
            }
        }
        return [
            'keys' => array_values(array_unique($keys)),
            'invalid' => array_values(array_unique($invalid)),
            'interpolated' => array_values(array_unique($interpolated)),
        ];
    }

    /**
     * Whether a value is a complete 1Password secret reference:
     * op://<vault>/<item>/[<section>/]<field>[?attribute=...]
     * Vault and item names may contain spaces.
     */
    public static function isValidReference(string $value): bool
    {
        if (preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            return false;
        }
        if (preg_match('#^op://([^/?]+)/([^/?]+)/(?:([^/?]+)/)?([^/?]+)(\?[A-Za-z0-9_=&.-]+)?$#', $value, $m) !== 1) {
            return false;
        }
        foreach ([$m[1], $m[2], $m[3], $m[4]] as $index => $segment) {
            if ($index === 2 && $segment === '') {
                continue; // optional section
            }
            if (trim($segment) === '' || trim($segment) !== $segment) {
                return false;
            }
        }
        return true;
    }

    /**
     * Collect service-level `env_file:` paths from compose YAML.
     *
     * Line-based so it works without the yaml extension. Handles the short
     * form, flow lists, block lists and the long `- path:` syntax.
     *
     * @return array{paths: string[], unresolvable: bool}
     */
    public static function extractServiceEnvFiles(string $yaml): array
    {
        $lines = preg_split('/\R/', $yaml) ?: [];
        $paths = [];
        $unresolvable = false;
        $count = count($lines);

        for ($i = 0; $i < $count; $i++) {
            if (preg_match('/^(\s*)(?:-\s+)?env_file\s*:\s*(.*)$/', $lines[$i], $m) !== 1) {
                continue;
            }
            $indent = strlen($m[1]);
            $rest = self::stripYamlComment($m[2]);

            if ($rest !== '') {
                if ($rest[0] === '[') {
                    if (!str_ends_with($rest, ']')) {
                        $unresolvable = true;
                        continue;
                    }
                    foreach (explode(',', substr($rest, 1, -1)) as $item) {
                        $paths[] = self::unquoteYamlScalar(trim($item));
                    }
                } elseif ($rest[0] === '{') {
                    if (preg_match('/\bpath\s*:\s*([^,}]+)/', $rest, $pm) === 1) {
                        $paths[] = self::unquoteYamlScalar(trim($pm[1]));
                    } else {
                        $unresolvable = true;
                    }
                } else {
                    $paths[] = self::unquoteYamlScalar($rest);
                }
                continue;
            }

            // Block form: following lines that are deeper, or list items at the same indent.
            for ($j = $i + 1; $j < $count; $j++) {
                $line = $lines[$j];
                if (trim($line) === '' || ltrim($line)[0] === '#') {
                    continue;
                }
                $lineIndent = strlen($line) - strlen(ltrim($line));
                $trimmed = ltrim($line);
                if (!($lineIndent > $indent || ($lineIndent === $indent && str_starts_with($trimmed, '- ')))) {
                    break;
                }
                $item = self::stripYamlComment($trimmed);
                if (str_starts_with($item, '- ')) {
                    $item = ltrim(substr($item, 2));
                }
                if (preg_match('/^path\s*:\s*(.+)$/', $item, $pm) === 1) {
                    $paths[] = self::unquoteYamlScalar(trim($pm[1]));
                } elseif (preg_match('/^(required|format)\s*:/', $item) === 1) {
                    continue;
                } elseif ($item !== '' && !str_contains($item, ': ')) {
                    $paths[] = self::unquoteYamlScalar($item);
                }
                $i = $j;
            }
        }

        $clean = [];
        foreach ($paths as $path) {
            if ($path === '') {
                continue;
            }
            if (str_contains($path, '$')) {
                $unresolvable = true;
                continue;
            }
            $clean[] = $path;
        }

        return ['paths' => array_values(array_unique($clean)), 'unresolvable' => $unresolvable];
    }

    /**
     * Whether compose YAML holds an `op://` reference outside comments.
     */
    public static function yamlContainsReference(string $yaml): bool
    {
        if (!str_contains($yaml, 'op://')) {
            return false;
        }
        foreach (preg_split('/\R/', $yaml) ?: [] as $line) {
            if (str_contains(self::stripYamlComment(trim($line)), 'op://')) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether compose YAML pulls in other files through `include:` or `extends: file:`.
     */
    private static function yamlUsesIncludeOrExtendsFile(string $yaml): bool
    {
        if (preg_match('/^include\s*:/m', $yaml) === 1) {
            return true;
        }
        if (preg_match('/^\s*extends\s*:\s*\{[^}]*\bfile\s*:/m', $yaml) === 1) {
            return true;
        }
        $lines = preg_split('/\R/', $yaml) ?: [];
        foreach ($lines as $i => $line) {
            if (preg_match('/^(\s*)extends\s*:\s*$/', $line, $m) !== 1) {
                continue;
            }
            $indent = strlen($m[1]);
            for ($j = $i + 1; $j < count($lines); $j++) {
                $next = $lines[$j];
                if (trim($next) === '') {
                    continue;
                }
                if (strlen($next) - strlen(ltrim($next)) <= $indent) {
                    break;
                }
                if (preg_match('/^\s*file\s*:/', $next) === 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Candidate on-disk locations for a service env_file entry. Compose
     * resolves relative paths from the project directory; the defining file's
     * directory is also checked so overrides in other folders are covered.
     *
     * @return string[] Existing files only
     */
    private static function resolveServiceEnvFileCandidates(string $path, string $projectDir, string $definingDir): array
    {
        if (str_starts_with($path, '~/')) {
            $path = (getenv('HOME') ?: '/root') . substr($path, 1);
        }
        $candidates = str_starts_with($path, '/')
            ? [$path]
            : [rtrim($projectDir, '/') . '/' . $path, rtrim($definingDir, '/') . '/' . $path];

        $existing = [];
        foreach (array_unique($candidates) as $candidate) {
            if (is_file($candidate)) {
                $existing[] = $candidate;
            }
        }
        return $existing;
    }

    private static function stripYamlComment(string $text): string
    {
        $text = trim($text);
        if ($text === '' || $text[0] === '#') {
            return '';
        }
        if (!str_contains($text, "'") && !str_contains($text, '"')) {
            $text = (string) preg_replace('/\s+#.*$/', '', $text);
        }
        return trim($text);
    }

    private static function unquoteYamlScalar(string $value): string
    {
        $value = trim($value);
        $len = strlen($value);
        if ($len >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[$len - 1] === $value[0]) {
            return substr($value, 1, -1);
        }
        return $value;
    }

    private static function unquoteEnvValue(string $value): string
    {
        $len = strlen($value);
        if ($len >= 2 && ($value[0] === '"' || $value[0] === "'") && $value[$len - 1] === $value[0]) {
            return substr($value, 1, -1);
        }
        // Unquoted values may carry an inline comment.
        return trim((string) preg_replace('/\s+#.*$/', '', $value));
    }

    /**
     * @param array<int, string|null> $files
     * @return array<int, int|false>
     */
    private static function mtimes(array $files): array
    {
        $times = [];
        foreach ($files as $file) {
            $times[] = ($file !== null && $file !== '' && is_file($file)) ? @filemtime($file) : false;
        }
        return $times;
    }

    // ---------------------------------------------------------------
    // Status
    // ---------------------------------------------------------------

    /**
     * Whether the op-secure helper used for deployments is installed.
     */
    public static function cliAvailable(): bool
    {
        return is_file(self::opSecureBin()) && is_executable(self::opSecureBin());
    }

    /**
     * Whether the service-account token is loaded in RAM. Only presence and
     * size are checked; the file is never opened.
     */
    public static function tokenPresent(): bool
    {
        $token = self::tokenFile();
        clearstatcache(true, $token);
        return is_file($token) && (int) @filesize($token) > 0;
    }

    /**
     * Current 1Password state for display and deployment gating.
     *
     * unavailable: op-secure is not installed.
     * locked:      the RAM token file is absent (e.g. after a reboot).
     * unlocked:    the token is present and op-status (when installed)
     *              exits 0. Results from op-status are cached briefly so
     *              list refreshes do not repeat network checks.
     * error:       the token is present but op-status exits non-zero.
     *
     * @return array{state: string, label: string, detail: string}
     */
    public static function status(bool $useCache = true): array
    {
        if (!self::cliAvailable()) {
            return self::statusPayload(self::STATE_UNAVAILABLE);
        }
        if (!self::tokenPresent()) {
            return self::statusPayload(self::STATE_LOCKED);
        }

        $statusBin = self::opStatusBin();
        if (!is_file($statusBin) || !is_executable($statusBin)) {
            return self::statusPayload(self::STATE_UNLOCKED);
        }

        $token = self::tokenFile();
        $fingerprint = (string) @filemtime($token) . ':' . (string) @fileinode($token);
        $cacheFile = self::statusCacheFile();
        if ($useCache && is_file($cacheFile)) {
            $cached = json_decode((string) @file_get_contents($cacheFile), true);
            if (
                is_array($cached)
                && ($cached['fingerprint'] ?? null) === $fingerprint
                && (time() - (int) ($cached['checkedAt'] ?? 0)) < self::STATUS_CACHE_TTL
                && in_array($cached['state'] ?? '', [self::STATE_UNLOCKED, self::STATE_ERROR], true)
            ) {
                return self::statusPayload((string) $cached['state']);
            }
        }

        $exitCode = self::runStatusCommand($statusBin);
        $state = $exitCode === 0 ? self::STATE_UNLOCKED : self::STATE_ERROR;

        $dir = dirname($cacheFile);
        if (is_dir($dir) || @mkdir($dir, 0700, true)) {
            @file_put_contents($cacheFile, json_encode([
                'state' => $state,
                'fingerprint' => $fingerprint,
                'checkedAt' => time(),
            ]));
            @chmod($cacheFile, 0600);
        }

        return self::statusPayload($state);
    }

    /**
     * Decide whether an operation that creates or recreates containers
     * (up, update) may run for a stack.
     *
     * Ordinary stacks are always allowed. 1Password stacks are allowed only
     * when their configuration is supported, secret-aware deployment is
     * enabled, and 1Password is unlocked; the caller then passes the env
     * file to compose.sh, which resolves the references with op-secure.
     *
     * @return array{allowed: bool, managed: bool, reason: ?string, message: ?string, envFile: ?string}
     */
    public static function deploymentGate(OnePasswordDetection $detection, ?bool $injectionEnabled = null): array
    {
        if (!$detection->uses) {
            return ['allowed' => true, 'managed' => false, 'reason' => null, 'message' => null, 'envFile' => null];
        }

        $blocker = $detection->getBlockReason();
        if ($blocker !== null) {
            return [
                'allowed' => false,
                'managed' => true,
                'reason' => 'unsupported',
                'message' => 'This project uses 1Password secrets, but its configuration cannot be deployed safely. ' . $blocker,
                'envFile' => $detection->envFile,
            ];
        }

        if (!($injectionEnabled ?? self::injectionEnabled())) {
            return [
                'allowed' => false,
                'managed' => true,
                'reason' => 'not_enabled',
                'message' => self::NOT_ENABLED_MESSAGE,
                'envFile' => $detection->envFile,
            ];
        }

        $state = self::status()['state'];
        if ($state !== self::STATE_UNLOCKED) {
            return [
                'allowed' => false,
                'managed' => true,
                'reason' => $state,
                'message' => self::messageForState($state),
                'envFile' => $detection->envFile,
            ];
        }

        // Unlocked: compose.sh resolves the references through op-secure at run time.
        return [
            'allowed' => true,
            'managed' => true,
            'reason' => null,
            'message' => null,
            'envFile' => $detection->envFile,
        ];
    }

    /**
     * Whether secret-aware deployment is enabled in plugin settings
     * (ONEPASSWORD_SECRET_INJECTION, default on).
     */
    public static function injectionEnabled(): bool
    {
        if (!function_exists('parse_plugin_cfg')) {
            return true;
        }
        $cfg = parse_plugin_cfg('compose.manager');
        return strtolower(trim((string) ($cfg['ONEPASSWORD_SECRET_INJECTION'] ?? 'true'))) !== 'false';
    }

    /**
     * Message shown when a 1Password project cannot be deployed in a given state.
     */
    public static function messageForState(string $state): string
    {
        switch ($state) {
            case self::STATE_UNAVAILABLE:
                return self::UNAVAILABLE_MESSAGE;
            case self::STATE_ERROR:
                return self::ERROR_MESSAGE;
            default:
                return self::LOCKED_MESSAGE;
        }
    }

    /**
     * Run op-status with output discarded; returns its exit code.
     */
    private static function runStatusCommand(string $statusBin): int
    {
        if (self::$statusRunner !== null) {
            return (int) (self::$statusRunner)($statusBin);
        }
        $output = [];
        $exitCode = 1;
        exec('timeout 10 ' . escapeshellarg($statusBin) . ' </dev/null >/dev/null 2>&1', $output, $exitCode);
        return $exitCode;
    }

    /**
     * @return array{state: string, label: string, detail: string}
     */
    private static function statusPayload(string $state): array
    {
        $labels = [
            self::STATE_UNLOCKED => 'Unlocked',
            self::STATE_LOCKED => 'Locked',
            self::STATE_UNAVAILABLE => 'Unavailable',
            self::STATE_ERROR => 'Check failed',
        ];
        $details = [
            self::STATE_UNLOCKED => 'The 1Password service-account token is loaded. 1Password projects can be deployed.',
            self::STATE_LOCKED => 'The 1Password token is not loaded. Run op-unlock on Unraid before deploying 1Password projects. Running containers are not affected.',
            self::STATE_UNAVAILABLE => 'The 1Password CLI helper (op-secure) is not installed on this server.',
            self::STATE_ERROR => 'The 1Password token is present but op-status reported a problem. Run op-status on Unraid for details.',
        ];
        return [
            'state' => $state,
            'label' => $labels[$state] ?? 'Unknown',
            'detail' => $details[$state] ?? '',
        ];
    }
}
