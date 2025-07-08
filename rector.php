<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Php74\Rector\Closure\ClosureToArrowFunctionRector;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Privatization\Rector\ClassMethod\PrivatizeFinalClassMethodRector;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig
        ->sets([
            LevelSetList::UP_TO_PHP_82,
            SetList::CODE_QUALITY,
            SetList::DEAD_CODE,
            SetList::PRIVATIZATION,
            SetList::NAMING,
            SetList::TYPE_DECLARATION,
            SetList::EARLY_RETURN,
            PHPUnitSetList::PHPUNIT_CODE_QUALITY,
            SetList::CODING_STYLE,
        ]);
    $rectorConfig
        ->paths([
            __DIR__ . '/src',
            __DIR__ . '/tests',
        ]);

    $rectorConfig->skip([
        PrivatizeFinalClassMethodRector::class,
        ClosureToArrowFunctionRector::class
    ]);

    $rectorConfig->phpstanConfig(__DIR__ . '/phpstan.neon');
};