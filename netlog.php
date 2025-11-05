#!/usr/bin/php
<?php

$ouiFile = __DIR__ . '/oui.txt';
$colorFile = __DIR__ . '/mac_colors.json';
$disconnectConfigFile = __DIR__ . '/disconnect_reasons.json';
$vlanConfigFile = __DIR__ . '/vlan_ids.json';

function loadOUI($filename) {
    $vendors = [];

    if (!file_exists($filename)) {
        echo "OUI file not found. Downloading from IEEE...\n";
        $url = "http://standards-oui.ieee.org/oui/oui.txt";
        $data = @file_get_contents($url);
        if ($data === false) {
            fwrite(STDERR, "Failed to download OUI file from $url\n");
            return $vendors;
        }
        file_put_contents($filename, $data);
    }

    $handle = fopen($filename, 'r');
    if (!$handle) {
        fwrite(STDERR, "Failed to open OUI file.\n");
        return $vendors;
    }

    while (($line = fgets($handle)) !== false) {
        if (preg_match('/^([0-9A-Fa-f]{6})\s+\(hex\)\s+(.+)$/', $line, $m)) {
            $vendors[strtoupper($m[1])] = trim($m[2]);
        }
    }
    fclose($handle);
    return $vendors;
}

function colorize($text, $color) {
    return "\033[" . $color . "m" . $text . "\033[0m";
}

function highlightSearchTerm($line, $term, $isRegex = false) {
    $callback = function ($m) {
        // Bright white background with black text and 3 spaces padding
        return "\033[1;30;107m   " . $m[0] . "   \033[0m";
    };

    if ($isRegex) {
        return @preg_replace_callback("/$term/i", $callback, $line);
    } else {
        return preg_replace_callback(
            '/' . preg_quote($term, '/') . '/i',
            $callback,
            $line
        );
    }
}

function drawStatusBar($searchTerm, $searchIsRegex, $filter) {
    $mode = $searchIsRegex ? "REGEX" : "TEXT";
    $filterText = $filter ? " | Filter: $filter" : "";
    echo colorize("[Search: $searchTerm ($mode)]$filterText", '0;37') . "\n";
    echo colorize("Keys: ↑↓/WS = scroll, PgUp/PgDn/Space = page, / = search, n = next, f = filter, r = toggle search mode, e = export, c = clear, q = quit", '0;36') . "\n";
}

function saveColorMap($file, $map, $index) {
    file_put_contents($file, json_encode(['map' => $map, 'index' => $index], JSON_PRETTY_PRINT));
}

function loadConfigMap($file) {
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if (is_array($data)) {
            return $data;
        }
    }

    // Create an empty config file so the user can edit it later
    file_put_contents($file, json_encode(new stdClass(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    return [];
}

function saveConfigMap($file, $map) {
    file_put_contents($file, json_encode($map, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function highlightLine($line, $vendors, &$macColorMap, &$nextColorIndex, $colorPalette, $searchTerm = null, $searchIsRegex = false) {
    global $disconnectReasonMap, $vlanIdMap;

    // Colorize MAC addresses with vendor, persistent per MAC
    preg_match_all('/(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/', $line, $matches, PREG_OFFSET_CAPTURE);
    $macs = $matches[0] ?? [];
    usort($macs, function ($a, $b) {
        return $b[1] <=> $a[1];
    });

    foreach ($macs as $entry) {
        list($mac, $pos) = $entry;
        $norm   = strtoupper(str_replace([':', '-'], '', $mac));
        $prefix = substr($norm, 0, 6);
        $vendor = $vendors[$prefix] ?? 'Unknown';

        if (!isset($macColorMap[$norm])) {
            $macColorMap[$norm] = $colorPalette[$nextColorIndex % count($colorPalette)];
            $nextColorIndex++;
        }

        $color   = $macColorMap[$norm];
        $colored = colorize("{$mac} ({$vendor})", $color);
        $line    = substr_replace($line, $colored, $pos, strlen($mac));
    }

    // Colorize IP addresses (blue text)
    $line = preg_replace_callback(
        '/\b(?:\d{1,3}\.){3}\d{1,3}\b/',
        function ($m) {
            return colorize($m[0], '1;34');
        },
        $line
    );

    // Highlight any word containing "fail" (any case) in DARK RED background, white text
    $line = preg_replace_callback(
        '/\b\w*fail\w*\b/i',
        function ($m) {
            return "\033[1;37;41m" . $m[0] . "\033[0m";
        },
        $line
    );

    // Highlight "clientJoin" in GREEN background with black text
    $line = preg_replace(
        '/clientJoin/',
        "\033[1;30;42mclientJoin\033[0m",
        $line
    );

    // Highlight "clientDisconnect" in PINK (magenta) background with black text
    $line = preg_replace(
        '/clientDisconnect/',
        "\033[1;30;45mclientDisconnect\033[0m",
        $line
    );

    // Highlight "userName"="XXXXX" OR any email address with YELLOW background, black text
    $line = preg_replace_callback(
        '/"userName"="[^"]+"|[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/',
        function ($m) {
            // Yellow background (43) with black text (30)
            return "\033[1;30;43m" . $m[0] . "\033[0m";
        },
        $line
    );

    // Highlight vlanId values with BLUE background and white text,
    // and append a human-readable explanation from the config file.
    $line = preg_replace_callback(
        '/"vlanId"="(\d+)"/',
        function ($m) use (&$vlanIdMap) {
            $id = $m[1];

            if (!isset($vlanIdMap[$id])) {
                // Seed with a default so the user can customize it in the config file
                $vlanIdMap[$id] = "VLAN {$id}";
            }

            $desc  = $vlanIdMap[$id];
            $label = '"vlanId"="' . $id . '" (' . $desc . ')';

            // Standard BLUE background with white text
            return "\033[1;97;44m" . $label . "\033[0m";
        },
        $line
    );

    // Highlight disconnectReason values with BLUE background and white text,
    // and append a human-readable explanation from the config file.
    $line = preg_replace_callback(
        '/"disconnectReason"="(\d+)"/',
        function ($m) use (&$disconnectReasonMap) {
            $code = $m[1];

            if (!isset($disconnectReasonMap[$code])) {
                // Seed with a default so the user can customize it in the config file
                $disconnectReasonMap[$code] = "Reason code {$code}";
            }

            $desc  = $disconnectReasonMap[$code];
            $label = '"disconnectReason"="' . $code . '" (' . $desc . ')';

            // Standard BLUE background with white text
            return "\033[1;97;44m" . $label . "\033[0m";
        },
        $line
    );

    // Highlight "apName"="..."" with the same BLUE background and white text
    $line = preg_replace_callback(
        '/"apName"="([^"]+)"/',
        function ($m) {
            $label = '"apName"="' . $m[1] . '"';
            return "\033[1;97;44m" . $label . "\033[0m";
        },
        $line
    );

    // Highlight "apLocation"="..."" with the same BLUE background and white text
    $line = preg_replace_callback(
        '/"apLocation"="([^"]+)"/',
        function ($m) {
            $label = '"apLocation"="' . $m[1] . '"';
            return "\033[1;97;44m" . $label . "\033[0m";
        },
        $line
    );

    // Apply search highlighting last so it stands out
    if ($searchTerm) {
        $line = highlightSearchTerm($line, $searchTerm, $searchIsRegex);
    }

    // Prefix each printed log line with a red "# "
    $line = "\033[1;31m#\033[0m " . $line;

    return $line;
}

$colorPalette = ['1;31','1;33','1;35','1;36','0;37','0;33','0;36','0;35'];

$disconnectReasonMap = loadConfigMap($disconnectConfigFile);
$vlanIdMap = loadConfigMap($vlanConfigFile);

$vendors = loadOUI($ouiFile);
$macColorMap = [];
$nextColorIndex = 0;

if (file_exists($colorFile)) {
    $json = json_decode(file_get_contents($colorFile), true);
    $macColorMap = $json['map'] ?? [];
    $nextColorIndex = $json['index'] ?? 0;
}

$tailMode = false;
$logFile = null;
$tailLines = 10;

for ($i = 1; $i < count($argv); $i++) {
    $arg = $argv[$i];
    if ($arg === '-f') {
        $tailMode = true;
    } elseif ($arg === '-n' && isset($argv[$i + 1]) && is_numeric($argv[$i + 1])) {
        $tailLines = (int)$argv[++$i];
    } elseif ($arg[0] !== '-') {
        $logFile = $arg;
    }
}

if (!$logFile && posix_isatty(STDIN)) {
    fwrite(STDERR, "Usage: php netlog.php [-f -n <lines>] <logfile> OR cat logfile | php netlog.php\n");
    exit(1);
}

$lines = [];
if (!posix_isatty(STDIN)) {
    while (($line = fgets(STDIN)) !== false) {
        $lines[] = rtrim($line);
    }
} elseif (file_exists($logFile)) {
    $lines = file($logFile, FILE_IGNORE_NEW_LINES);
}

$filteredLines = $lines;
$total = count($filteredLines);
$termHeight = (int)shell_exec('tput lines') - 4;
$offset = 0;
$searchTerm = null;
$searchIsRegex = false;
$filter = null;
$searchMatches = [];
$currentMatchIndex = -1;

function applyFilterAndSearch($lines, $searchTerm, $searchIsRegex, $filter) {
    $result = $lines;

    if ($filter !== null && $filter !== '') {
        $result = array_values(array_filter($result, function ($line) use ($filter) {
            return stripos($line, $filter) !== false;
        }));
    }

    if ($searchTerm !== null && $searchTerm !== '') {
        $result = array_values(array_filter($result, function ($line) use ($searchTerm, $searchIsRegex) {
            if ($searchIsRegex) {
                return @preg_match("/$searchTerm/i", $line);
            } else {
                return stripos($line, $searchTerm) !== false;
            }
        }));
    }

    return $result;
}

function buildSearchMatches($lines, $searchTerm, $searchIsRegex) {
    $matches = [];
    if ($searchTerm === null || $searchTerm === '') {
        return $matches;
    }
    foreach ($lines as $i => $line) {
        if ($searchIsRegex) {
            if (@preg_match("/$searchTerm/i", $line)) {
                $matches[] = $i;
            }
        } else {
            if (stripos($line, $searchTerm) !== false) {
                $matches[] = $i;
            }
        }
    }
    return $matches;
}

function render($lines, $offset, $termHeight, $vendors, &$macColorMap, &$nextColorIndex, $colorPalette, $searchTerm, $searchIsRegex) {
    system('clear');
    $max = min($offset + $termHeight, count($lines));
    for ($i = $offset; $i < $max; $i++) {
        $line = $lines[$i];
        echo highlightLine($line, $vendors, $macColorMap, $nextColorIndex, $colorPalette, $searchTerm, $searchIsRegex) . "\n";
    }
}

if (!posix_isatty(STDIN)) {
    // Piped input — stream mode
    foreach ($lines as $line) {
        echo highlightLine($line, $vendors, $macColorMap, $nextColorIndex, $colorPalette) . "\n";
    }
    saveColorMap($colorFile, $macColorMap, $nextColorIndex);
    saveConfigMap($disconnectConfigFile, $disconnectReasonMap);
    saveConfigMap($vlanConfigFile, $vlanIdMap);
    exit;
}

if ($tailMode) {
    // Tail Follow Mode
    $lastSize = filesize($logFile);

    $lastColorReload = time();

    // Print the last N lines
    $lines = file($logFile, FILE_IGNORE_NEW_LINES);
    $lastLines = array_slice($lines, -$tailLines);
    foreach ($lastLines as $line) {
        echo highlightLine($line, $vendors, $macColorMap, $nextColorIndex, $colorPalette) . "\n";
    }

    // Follow new lines
    $fp = fopen($logFile, 'r');
    if (!$fp) {
        fwrite(STDERR, "Failed to open log file for tail mode.\n");
        exit(1);
    }

    fseek($fp, $lastSize);

    while (true) {
        clearstatcache(true, $logFile);

        if (time() - $lastColorReload > 30) {
            if (file_exists($colorFile)) {
                $json = json_decode(file_get_contents($colorFile), true);
                $macColorMap = $json['map'] ?? $macColorMap;
                $nextColorIndex = $json['index'] ?? $nextColorIndex;
            }
            if (file_exists($disconnectConfigFile)) {
                $data = json_decode(file_get_contents($disconnectConfigFile), true);
                if (is_array($data)) {
                    $disconnectReasonMap = $data + $disconnectReasonMap;
                }
            }
            if (file_exists($vlanConfigFile)) {
                $data = json_decode(file_get_contents($vlanConfigFile), true);
                if (is_array($data)) {
                    $vlanIdMap = $data + $vlanIdMap;
                }
            }
            $lastColorReload = time();
        }

        $currentSize = filesize($logFile);
        if ($currentSize < $lastSize) {
            // Log rotated
            fclose($fp);
            $fp = fopen($logFile, 'r');
            fseek($fp, 0);
            $lastSize = 0;
        }

        while (($line = fgets($fp)) !== false) {
            $lastSize = ftell($fp);
            echo highlightLine(rtrim($line), $vendors, $macColorMap, $nextColorIndex, $colorPalette) . "\n";
        }

        saveColorMap($colorFile, $macColorMap, $nextColorIndex);
        saveConfigMap($disconnectConfigFile, $disconnectReasonMap);
        saveConfigMap($vlanConfigFile, $vlanIdMap);

        usleep(200000);
    }
}

// Interactive view mode
shell_exec('stty cbreak -echo');

$filteredLines = applyFilterAndSearch($lines, $searchTerm, $searchIsRegex, $filter);
$termHeight = (int)shell_exec('tput lines') - 4;
$offset = 0;
$searchMatches = buildSearchMatches($filteredLines, $searchTerm, $searchIsRegex);
$currentMatchIndex = -1;

render($filteredLines, $offset, $termHeight, $vendors, $macColorMap, $nextColorIndex, $colorPalette, $searchTerm, $searchIsRegex);
drawStatusBar($searchTerm ?? 'None', $searchIsRegex, $filter);

while (true) {
    $char = fread(STDIN, 1);

    if ($char === "\033") { // Escape sequence
        $char2 = fread(STDIN, 1);
        if ($char2 === '[') {
            $char3 = fread(STDIN, 1);
            if ($char3 === 'A') { // Up arrow
                $offset = max(0, $offset - 1);
            } elseif ($char3 === 'B') { // Down arrow
                $offset = min(max(0, count($filteredLines) - $termHeight), $offset + 1);
            } elseif ($char3 === '5') { // PgUp
                fread(STDIN, 1); // skip ~
                $offset = max(0, $offset - $termHeight);
            } elseif ($char3 === '6') { // PgDn
                fread(STDIN, 1); // skip ~
                $offset = min(max(0, count($filteredLines) - $termHeight), $offset + $termHeight);
            }
        }
    } elseif ($char === 'w' || $char === 'W') { // scroll up
        $offset = max(0, $offset - 1);
    } elseif ($char === 's' || $char === 'S') { // scroll down
        $offset = min(max(0, count($filteredLines) - $termHeight), $offset + 1);
    } elseif ($char === ' ') { // spacebar = page down
        $offset = min(max(0, count($filteredLines) - $termHeight), $offset + $termHeight);
    } elseif ($char === '/') { // search
        echo "\033[2K\rEnter search term: ";
        shell_exec('stty echo');
        $input = trim(fgets(STDIN));
        shell_exec('stty -echo');
        $searchTerm = $input !== '' ? $input : null;
        $offset = 0;
        $filteredLines = applyFilterAndSearch($lines, $searchTerm, $searchIsRegex, $filter);
        $searchMatches = buildSearchMatches($filteredLines, $searchTerm, $searchIsRegex);
        $currentMatchIndex = -1;
    } elseif ($char === 'n' || $char === 'N') { // next search result
        if (!empty($searchMatches)) {
            $currentMatchIndex = ($currentMatchIndex + 1) % count($searchMatches);
            $matchLine = $searchMatches[$currentMatchIndex];
            if ($matchLine < $offset || $matchLine >= $offset + $termHeight) {
                $offset = max(0, min($matchLine, max(0, count($filteredLines) - $termHeight)));
            }
        }
    } elseif ($char === 'f' || $char === 'F') { // filter
        echo "\033[2K\rEnter filter text (empty to clear): ";
        shell_exec('stty echo');
        $input = trim(fgets(STDIN));
        shell_exec('stty -echo');
        $filter = $input !== '' ? $input : null;
        $offset = 0;
        $filteredLines = applyFilterAndSearch($lines, $searchTerm, $searchIsRegex, $filter);
        $searchMatches = buildSearchMatches($filteredLines, $searchTerm, $searchIsRegex);
        $currentMatchIndex = -1;
    } elseif ($char === 'r' || $char === 'R') { // toggle search mode
        $searchIsRegex = !$searchIsRegex;
        $filteredLines = applyFilterAndSearch($lines, $searchTerm, $searchIsRegex, $filter);
        $searchMatches = buildSearchMatches($filteredLines, $searchTerm, $searchIsRegex);
        $currentMatchIndex = -1;
    } elseif ($char === 'e' || $char === 'E') { // export current view
        $exportFile = 'netlog_export_' . date('Ymd_His') . '.log';
        $start = $offset;
        $end = min($offset + $termHeight, count($filteredLines));
        $out = [];
        for ($i = $start; $i < $end; $i++) {
            $out[] = $filteredLines[$i];
        }
        file_put_contents($exportFile, implode("\n", $out));
        echo "\033[2K\rExported current view to $exportFile\n";
        usleep(500000);
    } elseif ($char === 'c' || $char === 'C') { // clear search and filter
        $filter = null;
        $searchTerm = null;
        $searchIsRegex = false;
        $offset = 0;
        $filteredLines = $lines;
        $searchMatches = [];
        $currentMatchIndex = -1;
    } elseif ($char === 'q') {
        break;
    }

    $offset = max(0, min($offset, max(0, count($filteredLines) - $termHeight)));
    render($filteredLines, $offset, $termHeight, $vendors, $macColorMap, $nextColorIndex, $colorPalette, $searchTerm, $searchIsRegex);
    drawStatusBar($searchTerm ?? 'None', $searchIsRegex, $filter);
    saveColorMap($colorFile, $macColorMap, $nextColorIndex);
    saveConfigMap($disconnectConfigFile, $disconnectReasonMap);
    saveConfigMap($vlanConfigFile, $vlanIdMap);
}

shell_exec('stty sane');
system('clear');
