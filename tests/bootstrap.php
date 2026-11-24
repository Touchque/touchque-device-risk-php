<?php

// Composer's autoloader when installed; else a PSR-4 loader for src/ and tests/, so the
// suite also runs with any PHPUnit 9 (e.g. the main SDK's vendor/bin/phpunit).
$autoload = __DIR__ . '/../vendor/autoload.php';
if (is_file($autoload)) {
    require $autoload;
}
spl_autoload_register(static function (string $class): void {
    foreach (['Touchque\\DeviceRisk\\Tests\\' => __DIR__ . '/', 'Touchque\\DeviceRisk\\' => __DIR__ . '/../src/'] as $prefix => $dir) {
        if (strpos($class, $prefix) === 0) {
            $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (is_file($file)) {
                require $file;
            }
            return;
        }
    }
});
