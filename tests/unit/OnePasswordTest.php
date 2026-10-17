<?php

declare(strict_types=1);

namespace ComposeManager\Tests;

use PluginTests\Mocks\FunctionMocks;
use PluginTests\TestCase;

require_once '/usr/local/emhttp/plugins/compose.manager/include/Util.php';
require_once '/usr/local/emhttp/plugins/compose.manager/include/ComposeCommandBuilder.php';
require_once '/usr/local/emhttp/plugins/compose.manager/include/Helpers.php';

/**
 * 1Password detection, status and deployment gating.
 *
 * The 1Password CLI is never called: binaries are fake files in a temp dir
 * and op-status is replaced with a runner callback. No real tokens are used.
 */
class OnePasswordTest extends TestCase
{
    private const FAKE_TOKEN = 'ops_FAKE_TEST_TOKEN_never_real_0123456789';
    private const SITESPEED_ENV = "GRAFANA_MCP_TOKEN=op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_TOKEN\n"
        . "GRAFANA_MCP_SERVER_TOKEN=op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_SERVER_TOKEN\n";
    private const SITESPEED_COMPOSE = "services:\n  grafana-mcp:\n    image: grafana/mcp-grafana:latest\n"
        . "    environment:\n      GRAFANA_SERVICE_ACCOUNT_TOKEN: \${GRAFANA_MCP_TOKEN}\n"
        . "      MCP_GRAFANA_SERVER_TOKEN: \${GRAFANA_MCP_SERVER_TOKEN}\n";

    private string $root;
    private string $binDir;
    private string $tokenFile;
    private string $cacheFile;
    private int $statusCalls = 0;
    private int $statusExit = 0;

    protected function setUp(): void
    {
        parent::setUp();
        \StackInfo::clearCache();
        $this->root = $this->createTempDir();
        $this->binDir = $this->createTempDir();
        $this->tokenFile = $this->binDir . '/run/service-account-token';
        $this->cacheFile = $this->binDir . '/status-cache.json';
        $this->statusCalls = 0;
        $this->statusExit = 0;
        $this->configureOnePassword();

        global $compose_root, $plugin_root, $sName;
        $compose_root = $this->root;
        $plugin_root = '/usr/local/emhttp/plugins/compose.manager/';
        $sName = 'compose.manager';
        FunctionMocks::setPluginConfig('compose.manager', ['PROJECTS_FOLDER' => $this->root, 'DEBUG_TO_LOG' => 'false']);
    }

    protected function tearDown(): void
    {
        \OnePassword::configure([]);
        \StackInfo::clearCache();
        $_POST = [];
        $_GET = [];
        parent::tearDown();
    }

    private function configureOnePassword(bool $withStatusBin = false): void
    {
        $paths = [
            'opSecure' => $this->binDir . '/op-secure',
            'tokenFile' => $this->tokenFile,
            'cacheFile' => $this->cacheFile,
            'opStatus' => $withStatusBin ? $this->binDir . '/op-status' : $this->binDir . '/missing-op-status',
        ];
        \OnePassword::configure($paths, function (): int {
            $this->statusCalls++;
            return $this->statusExit;
        });
    }

    private function installFakeCli(bool $withStatusBin = false): void
    {
        foreach ($withStatusBin ? ['op-secure', 'op-status'] : ['op-secure'] as $bin) {
            file_put_contents($this->binDir . '/' . $bin, "#!/bin/sh\nexit 0\n");
            chmod($this->binDir . '/' . $bin, 0755);
        }
        $this->configureOnePassword($withStatusBin);
    }

    private function unlock(): void
    {
        @mkdir(dirname($this->tokenFile), 0700, true);
        file_put_contents($this->tokenFile, self::FAKE_TOKEN);
        chmod($this->tokenFile, 0600);
    }

    /**
     * @param array<string, string> $files filename => content
     */
    private function createStack(string $name, array $files): string
    {
        $dir = $this->root . '/' . $name;
        mkdir($dir, 0755, true);
        foreach ($files as $file => $content) {
            if (!is_dir(dirname("$dir/$file"))) {
                mkdir(dirname("$dir/$file"), 0755, true);
            }
            file_put_contents("$dir/$file", $content);
        }
        file_put_contents("$dir/name", $name);
        return $dir;
    }

    private function detect(string $name): \OnePasswordDetection
    {
        return \StackInfo::fromProject($this->root, $name)->getOnePasswordDetection();
    }

    private function startArray(): void
    {
        $varIniDir = $this->createTempDir();
        file_put_contents("$varIniDir/var.ini", "mdState=STARTED\nfsState=Started\n");
        \PluginTests\StreamWrapper\UnraidStreamWrapper::addMapping('/var/local/emhttp/var.ini', "$varIniDir/var.ini");
    }

    // ===========================================
    // Reference parsing
    // ===========================================

    public function testValidReferencesIncludingSpacesAndSections(): void
    {
        $this->assertTrue(\OnePassword::isValidReference('op://Homelab Secrets/Sitespeed - Grafana MCP/GRAFANA_MCP_TOKEN'));
        $this->assertTrue(\OnePassword::isValidReference('op://Homelab Secrets/VehicleHub/DATABASE_PASSWORD'));
        $this->assertTrue(\OnePassword::isValidReference('op://vault/item/section/field'));
        $this->assertTrue(\OnePassword::isValidReference('op://vault/item/field?attribute=otp'));
    }

    public function testInvalidReferences(): void
    {
        foreach ([
            'op://',
            'op://vault',
            'op://vault/item',
            'op:///item/field',
            'op://vault//field',
            'op://vault/item/a/b/c',
            'prefix-op://vault/item/field',
            'op://vault/ item/field',
            "op://vault/item/fi\teld",
        ] as $ref) {
            $this->assertFalse(\OnePassword::isValidReference($ref), "Expected invalid: $ref");
        }
    }

    public function testParseEnvReferencesHandlesQuotesExportAndComments(): void
    {
        $parsed = \OnePassword::parseEnvReferences(implode("\n", [
            '# DB_PASSWORD=op://Vault/Commented/out',
            'PLAIN=hello',
            'export API_KEY=op://Vault/App/api key',
            'QUOTED="op://Vault/App/quoted"',
            "SINGLE='op://Vault/App/single'",
            'TRAILING=op://Vault/App/trailing # inline comment',
            'BROKEN=op://Vault/App',
            'EMBEDDED=postgres://u:op://Vault/App/pw@db',
        ]));

        $this->assertSame(['API_KEY', 'QUOTED', 'SINGLE', 'TRAILING'], $parsed['keys']);
        $this->assertSame(['BROKEN', 'EMBEDDED'], $parsed['invalid']);
    }

    // ===========================================
    // Detection via StackInfo
    // ===========================================

    public function testOrdinaryProjectIsNotManaged(): void
    {
        $this->createStack('paperless', [
            'compose.yaml' => "services:\n  app:\n    image: paperless\n    environment:\n      DB_PASS: \${DB_PASS}\n",
            '.env' => "DB_PASS=plain-value\n",
        ]);
        $detection = $this->detect('paperless');
        $this->assertFalse($detection->uses);
        $this->assertNull($detection->getBlockReason());
        $this->assertTrue(\OnePassword::deploymentGate($detection)['allowed']);
    }

    public function testSitespeedEnvReferencesAreDetectedAndDeployable(): void
    {
        $dir = $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);
        $detection = $this->detect('sitespeedio');

        $this->assertTrue($detection->uses);
        $this->assertTrue($detection->isDeployable());
        $this->assertSame($dir . '/.env', $detection->envFile);
        $this->assertSame(['GRAFANA_MCP_TOKEN', 'GRAFANA_MCP_SERVER_TOKEN'], $detection->envKeys);
    }

    public function testDetectionDoesNotDependOnLockStateOrCli(): void
    {
        // Simulates the state after an Unraid reboot: no token file, no CLI.
        $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);
        $this->assertFileDoesNotExist($this->tokenFile);
        $this->assertSame(\OnePassword::STATE_UNAVAILABLE, \OnePassword::status()['state']);
        $this->assertTrue($this->detect('sitespeedio')->uses);

        $this->installFakeCli();
        $this->assertSame(\OnePassword::STATE_LOCKED, \OnePassword::status()['state']);
        \StackInfo::clearCache();
        $this->assertTrue($this->detect('sitespeedio')->uses);
        $this->assertSame(0, $this->statusCalls, 'Detection must not run any status command');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function composeFileNameProvider(): array
    {
        return [
            'compose.yaml' => ['compose.yaml'],
            'compose.yml' => ['compose.yml'],
            'docker-compose.yaml' => ['docker-compose.yaml'],
            'docker-compose.yml' => ['docker-compose.yml'],
        ];
    }

    /**
     * @dataProvider composeFileNameProvider
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('composeFileNameProvider')]
    public function testDetectionWorksForEveryComposeFileName(string $fileName): void
    {
        $this->createStack('vehiclehub', [
            $fileName => "services:\n  api:\n    image: vehiclehub\n    environment:\n      DATABASE_PASSWORD: \${DATABASE_PASSWORD}\n",
            '.env' => "DATABASE_PASSWORD=op://Homelab Secrets/VehicleHub/DATABASE_PASSWORD\n",
        ]);
        $detection = $this->detect('vehiclehub');
        $this->assertTrue($detection->uses);
        $this->assertTrue($detection->isDeployable());
    }

    public function testExternalEnvPathIsScanned(): void
    {
        $external = $this->createTempDir() . '/secrets dir';
        mkdir($external, 0755, true);
        file_put_contents("$external/app.env", "DATABASE_PASSWORD=op://Homelab Secrets/VehicleHub/DATABASE_PASSWORD\n");
        $this->createStack('vehiclehub', [
            'compose.yaml' => "services:\n  api:\n    image: vehiclehub\n",
            '.env' => "UNUSED=plain\n",
            'envpath' => "$external/app.env",
        ]);

        $detection = $this->detect('vehiclehub');
        $this->assertTrue($detection->uses);
        $this->assertSame("$external/app.env", $detection->envFile);
    }

    public function testExternalComposeDirectoryIsScanned(): void
    {
        $external = $this->createTempDir() . '/immich';
        mkdir($external, 0755, true);
        file_put_contents("$external/docker-compose.yml", "services:\n  server:\n    image: immich\n");
        file_put_contents("$external/.env", "DB_PASSWORD=op://Homelab Secrets/Immich/DB_PASSWORD\n");
        $this->createStack('immich', ['indirect' => $external]);

        $detection = $this->detect('immich');
        $this->assertTrue($detection->uses);
        $this->assertSame("$external/.env", $detection->envFile);
    }

    public function testMissingEnvPathFallsBackWithoutError(): void
    {
        $this->createStack('broken-envpath', [
            'compose.yaml' => "services:\n  api:\n    image: x\n",
            'envpath' => '/does/not/exist.env',
        ]);
        $detection = $this->detect('broken-envpath');
        $this->assertFalse($detection->uses);
    }

    public function testLiteralReferenceInOverrideFileIsUnsupported(): void
    {
        $this->createStack('override-literal', [
            'compose.yaml' => "services:\n  app:\n    image: x\n",
            'compose.override.yaml' => "services:\n  app:\n    environment:\n      PASSWORD: op://Vault/App/password\n",
        ]);
        $detection = $this->detect('override-literal');
        $this->assertTrue($detection->uses);
        $this->assertFalse($detection->isDeployable());
        $this->assertStringContainsString('compose.override.yaml', (string) $detection->getBlockReason());
    }

    public function testCommentedReferenceInComposeFileIsIgnored(): void
    {
        $this->createStack('commented', [
            'compose.yaml' => "services:\n  app:\n    image: x\n    # PASSWORD: op://Vault/App/password\n",
        ]);
        $this->assertFalse($this->detect('commented')->uses);
    }

    public function testServiceEnvFileWithReferencesIsUnsupported(): void
    {
        $this->createStack('envfile-service', [
            'compose.yaml' => "services:\n  app:\n    image: x\n    env_file:\n      - path: ./app.env\n        required: false\n",
            'app.env' => "DB_PASSWORD=op://Vault/App/DB_PASSWORD\n",
        ]);
        $detection = $this->detect('envfile-service');
        $this->assertTrue($detection->uses);
        $this->assertFalse($detection->isDeployable());
        $this->assertStringContainsString('env_file app.env', (string) $detection->getBlockReason());
    }

    public function testServiceEnvFilePointingAtProjectEnvIsUnsupported(): void
    {
        $this->createStack('envfile-dotenv', [
            'compose.yaml' => "services:\n  app:\n    image: x\n    env_file: .env\n",
            '.env' => "DB_PASSWORD=op://Vault/App/DB_PASSWORD\n",
        ]);
        $detection = $this->detect('envfile-dotenv');
        $this->assertTrue($detection->uses);
        $this->assertFalse($detection->isDeployable());
    }

    public function testServiceEnvFileWithoutReferencesStaysOrdinary(): void
    {
        $this->createStack('envfile-plain', [
            'compose.yaml' => "services:\n  app:\n    image: x\n    env_file: [common.env, \"other.env\"]\n",
            'common.env' => "TZ=UTC\n",
        ]);
        $this->assertFalse($this->detect('envfile-plain')->uses);
    }

    public function testIncludeDirectiveBlocksOnlyManagedProjects(): void
    {
        $this->createStack('include-plain', ['compose.yaml' => "include:\n  - other.yaml\nservices:\n  app:\n    image: x\n"]);
        $this->assertFalse($this->detect('include-plain')->uses);

        $this->createStack('include-managed', [
            'compose.yaml' => "include:\n  - other.yaml\nservices:\n  app:\n    image: x\n",
            '.env' => "DB_PASSWORD=op://Vault/App/DB_PASSWORD\n",
        ]);
        $detection = $this->detect('include-managed');
        $this->assertTrue($detection->uses);
        $this->assertFalse($detection->isDeployable());
    }

    public function testInvalidReferenceBlocksDeployment(): void
    {
        $this->createStack('invalid-ref', [
            'compose.yaml' => "services:\n  app:\n    image: x\n",
            '.env' => "DB_PASSWORD=op://Vault/OnlyItem\n",
        ]);
        $detection = $this->detect('invalid-ref');
        $this->assertTrue($detection->uses);
        $this->assertSame(['DB_PASSWORD'], $detection->invalidKeys);
        $gate = \OnePassword::deploymentGate($detection);
        $this->assertFalse($gate['allowed']);
        $this->assertSame('unsupported', $gate['reason']);
        $this->assertStringContainsString('DB_PASSWORD', (string) $gate['message']);
    }

    public function testExtractServiceEnvFilesForms(): void
    {
        $yaml = "services:\n"
            . "  a:\n    env_file: a.env\n"
            . "  b:\n    env_file: [\"b1.env\", b2.env]\n"
            . "  c:\n    env_file:\n      - c1.env\n      - path: c2.env\n        required: false\n"
            . "  d:\n    env_file:\n    - d.env\n"
            . "  e:\n    env_file: \${ENV_DIR}/e.env\n";
        $result = \OnePassword::extractServiceEnvFiles($yaml);
        $this->assertSame(['a.env', 'b1.env', 'b2.env', 'c1.env', 'c2.env', 'd.env'], $result['paths']);
        $this->assertTrue($result['unresolvable']);
    }

    // ===========================================
    // Phase 1 gate and command builder
    // ===========================================

    public function testGateBlocksManagedProjectsAndAllowsOrdinary(): void
    {
        $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);
        $this->createStack('ordinary', ['compose.yaml' => "services:\n  app:\n    image: x\n"]);

        $this->assertTrue(\OnePassword::deploymentGate($this->detect('ordinary'))['allowed']);
        $gate = \OnePassword::deploymentGate($this->detect('sitespeedio'));
        $this->assertFalse($gate['allowed']);
        $this->assertTrue($gate['managed']);
    }

    public function testCommandBuilderReportsOnePasswordOnlyForContainerCreatingActions(): void
    {
        $dir = $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);

        foreach (['up', 'update'] as $action) {
            $op = \ComposeCommandBuilder::fromProject($this->root, 'sitespeedio', $action)['onePassword'];
            $this->assertTrue($op['managed'], $action);
            $this->assertSame("$dir/.env", $op['envFile'], $action);
            $this->assertSame('', $op['blocker'], $action);
        }
        foreach (['down', 'pull', 'stop', 'logs'] as $action) {
            $op = \ComposeCommandBuilder::fromProject($this->root, 'sitespeedio', $action)['onePassword'];
            $this->assertFalse($op['managed'], $action);
        }
    }

    public function testCommandBuilderReportsBlockerForUnsupportedConfig(): void
    {
        $this->createStack('envfile-dotenv', [
            'compose.yaml' => "services:\n  app:\n    image: x\n    env_file: .env\n",
            '.env' => "DB_PASSWORD=op://Vault/App/DB_PASSWORD\n",
        ]);
        $op = \ComposeCommandBuilder::fromProject($this->root, 'envfile-dotenv', 'up')['onePassword'];
        $this->assertTrue($op['managed']);
        $this->assertSame('', $op['envFile']);
        $this->assertNotSame('', $op['blocker']);
    }

    public function testEchoComposeCommandBlocksUpAndUpdateForManagedProject(): void
    {
        $dir = $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);
        $this->startArray();

        foreach (['up', 'update'] as $action) {
            \StackInfo::clearCache();
            $_POST = ['path' => $dir, 'profile' => ''];
            ob_start();
            echoComposeCommand($action, ['background' => true]);
            $output = (string) ob_get_clean();
            $payload = json_decode($output, true);
            $this->assertIsArray($payload, $action);
            $this->assertSame('onepassword', $payload['error'], $action);
            $this->assertStringContainsString('1Password', $payload['message']);
            $this->assertStringNotContainsString('op://', $output);
        }
    }

    public function testEchoComposeCommandAllowsReadOnlyAndStopActionsForManagedProject(): void
    {
        $dir = $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);
        $this->startArray();

        foreach (['logs', 'stop', 'down', 'pull'] as $action) {
            \StackInfo::clearCache();
            $_POST = ['path' => $dir, 'profile' => ''];
            ob_start();
            echoComposeCommand($action);
            $output = (string) ob_get_clean();
            $this->assertStringContainsString('ShowTtyd.php', $output, $action);
        }
    }

    public function testEchoComposeCommandMultipleSkipsManagedProjects(): void
    {
        $managed = $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);
        $this->startArray();

        ob_start();
        echoComposeCommandMultiple('up', ['paths' => [$managed]]);
        $payload = json_decode((string) ob_get_clean(), true);
        $this->assertIsArray($payload);
        $this->assertSame('onepassword', $payload['error']);
        $this->assertSame(['sitespeedio'], $payload['stacks']);
    }

    // ===========================================
    // Status
    // ===========================================

    public function testStatusStates(): void
    {
        $this->assertSame(\OnePassword::STATE_UNAVAILABLE, \OnePassword::status()['state']);

        $this->installFakeCli();
        $locked = \OnePassword::status();
        $this->assertSame(\OnePassword::STATE_LOCKED, $locked['state']);
        $this->assertSame('Locked', $locked['label']);

        $this->unlock();
        $this->assertSame(\OnePassword::STATE_UNLOCKED, \OnePassword::status()['state']);

        file_put_contents($this->tokenFile, '');
        $this->assertSame(\OnePassword::STATE_LOCKED, \OnePassword::status()['state']);
    }

    public function testStatusUsesOpStatusExitCodeAndCachesIt(): void
    {
        $this->installFakeCli(true);
        $this->unlock();

        $this->assertSame(\OnePassword::STATE_UNLOCKED, \OnePassword::status()['state']);
        $this->assertSame(\OnePassword::STATE_UNLOCKED, \OnePassword::status()['state']);
        $this->assertSame(1, $this->statusCalls, 'op-status result should be cached');

        $this->statusExit = 1;
        $this->assertSame(\OnePassword::STATE_ERROR, \OnePassword::status(false)['state']);
        $this->assertSame(2, $this->statusCalls);

        // Locking skips op-status entirely.
        unlink($this->tokenFile);
        $this->assertSame(\OnePassword::STATE_LOCKED, \OnePassword::status()['state']);
        $this->assertSame(2, $this->statusCalls);
    }

    public function testStatusAndCacheNeverContainTheToken(): void
    {
        $this->installFakeCli(true);
        $this->unlock();
        $status = \OnePassword::status();

        $this->assertStringNotContainsString(self::FAKE_TOKEN, (string) json_encode($status));
        $this->assertFileExists($this->cacheFile);
        $this->assertStringNotContainsString(self::FAKE_TOKEN, (string) file_get_contents($this->cacheFile));
    }

    // ===========================================
    // Rendered UI
    // ===========================================

    private function renderRows(): string
    {
        global $compose_root, $plugin_root, $sName;
        $compose_root = $this->root;
        $plugin_root = '/usr/local/emhttp/plugins/compose.manager/';
        $sName = 'compose.manager';
        $_GET = [];
        ob_start();
        include '/usr/local/emhttp/plugins/compose.manager/include/ComposeList.php';
        return (string) ob_get_clean();
    }

    private function renderRow(string $project): string
    {
        global $compose_root, $plugin_root, $sName;
        $compose_root = $this->root;
        $plugin_root = '/usr/local/emhttp/plugins/compose.manager/';
        $sName = 'compose.manager';
        $_GET = ['mode' => 'row', 'project' => $project];
        ob_start();
        include '/usr/local/emhttp/plugins/compose.manager/include/ComposeList.php';
        $payload = json_decode((string) ob_get_clean(), true);
        $this->assertIsArray($payload);
        return (string) ($payload['html'] ?? '');
    }

    public function testStackListShowsIndicatorOnlyForManagedProjects(): void
    {
        $this->createStack('sitespeedio', [
            'compose.yaml' => self::SITESPEED_COMPOSE,
            '.env' => self::SITESPEED_ENV . "PLAIN_SECRET=super-secret-plain-value\n",
        ]);
        $this->createStack('paperless', ['compose.yaml' => "services:\n  app:\n    image: x\n"]);

        $html = $this->renderRows();

        $this->assertMatchesRegularExpression("/data-project='sitespeedio'[^>]*data-onepassword='1'/", $html);
        $this->assertMatchesRegularExpression("/data-project='paperless'[^>]*data-onepassword='0'/", $html);
        $this->assertSame(1, substr_count($html, "class='compose-op-indicator'"));
        $this->assertStringContainsString(\OnePassword::INDICATOR_TOOLTIP, $html);
        // Neither references nor env values are rendered.
        $this->assertStringNotContainsString('op://', $html);
        $this->assertStringNotContainsString('super-secret-plain-value', $html);
    }

    public function testRowRefreshKeepsIndicatorForStoppedAndRunningStacks(): void
    {
        $this->createStack('sitespeedio', ['compose.yaml' => self::SITESPEED_COMPOSE, '.env' => self::SITESPEED_ENV]);

        $stopped = $this->renderRow('sitespeedio');
        $this->assertStringContainsString("class='compose-op-indicator'", $stopped);

        // Running: pre-populate the container cache the row renderer reads.
        \StackInfo::fromProject($this->root, 'sitespeedio')->setContainerList([
            ['Names' => 'sitespeedio-grafana-mcp-1', 'ID' => 'abcdef1234567890', 'State' => 'running', 'Status' => 'Up 5 minutes'],
        ]);
        $running = $this->renderRow('sitespeedio');
        $this->assertStringContainsString("class='compose-op-indicator'", $running);
        $this->assertStringContainsString('1 / 1', $running);
    }

    public function testStackListShowsConfigWarningForUnsupportedPattern(): void
    {
        $this->createStack('envfile-dotenv', [
            'compose.yaml' => "services:\n  app:\n    image: x\n    env_file: .env\n",
            '.env' => "DB_PASSWORD=op://Vault/App/DB_PASSWORD\n",
        ]);
        $html = $this->renderRows();
        $this->assertStringContainsString("compose-op-config-warning", $html);
        $this->assertStringContainsString("data-onepassword-blocked='1'", $html);
    }
}
