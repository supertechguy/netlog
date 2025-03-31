#!/usr/bin/php
<?php

$ouiFile = __DIR__ . '/oui.txt';
$colorFile = __DIR__ . '/mac_colors.json';

function loadOUI($filename) {
    $vendors = [];

    if (!file_exists($filename)) {
        echo "OUI file not found. Downloading from IEEE...
";
        $url = "http://standards-oui.ieee.org/oui/oui.txt";
        $data = @file_get_contents($url);
        if ($data === false) {
            fwrite(STDERR, "Failed to download OUI file from $url
");
            return $vendors;
        }
        file_put_contents($filename, $data);
    }

    $handle = fopen($filename, 'r');
    while ($line = fgets($handle)) {
        if (preg_match('/^([0-9A-F]{6})\s+\(base 16\)\s+(.+)$/i', $line, $m)) {
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
    if ($isRegex) {
        return @preg_replace_callback("/$term/i", fn($m) => "\033[1;30;43m" . $m[0] . "\033[0m", $line);
    } else {
        return preg_replace_callback(
            '/' . preg_quote($term, '/') . '/i',
            fn($m) => "\033[1;30;43m" . $m[0] . "\033[0m",
            $line
        );
    }
}

function drawStatusBar($searchTerm, $searchIsRegex, $filter) {
    $mode = $searchIsRegex ? "REGEX" : "TEXT";
    $filterText = $filter ? " | Filter: $filter" : "";
    echo colorize("[Search: $searchTerm ($mode)]$filterText", '0;37') . "\n";
    echo colorize("Keys: ↑↓/WS = scroll, PgUp/PgDn = page, / = text search, r = regex, n = next, f = filter (text or r:regex), e = export view, c = clear, q = quit", '0;36') . "\n";
}

function saveColorMap($file, $map, $index) {
    file_put_contents($file, json_encode(['map' => $map, 'index' => $index], JSON_PRETTY_PRINT));
}

function highlightLine($line, $vendors, &$macColorMap, &$nextColorIndex, $colorPalette, $searchTerm = null, $searchIsRegex = false) {
    preg_match_all('/(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}/', $line, $matches, PREG_OFFSET_CAPTURE);
    $macs = $matches[0] ?? [];
    usort($macs, fn($a, $b) => $b[1] <=> $a[1]);

    foreach ($macs as [$mac, $pos]) {
        $norm = strtoupper(str_replace([':', '-'], '', $mac));
        $prefix = substr($norm, 0, 6);
        $vendor = $vendors[$prefix] ?? 'Unknown';
        if (!isset($macColorMap[$norm])) {
            $macColorMap[$norm] = $colorPalette[$nextColorIndex % count($colorPalette)];
            $nextColorIndex++;
        }
        $color = $macColorMap[$norm];
        $colored = colorize("{$mac} ({$vendor})", $color);
        $line = substr_replace($line, $colored, $pos, strlen($mac));
    }

    $line = preg_replace_callback('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', fn($m) => colorize($m[0], '1;34'), $line);

    if ($searchTerm) {
        $line = highlightSearchTerm($line, $searchTerm, $searchIsRegex);
    }
    return $line;
}

$colorPalette = ['1;31','1;33','1;35','1;36','0;37','0;33','0;36','0;35'];
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


if (!$tailMode && !$logFile && posix_isatty(STDIN)) {
    fwrite(STDERR, "Usage: netlog [-f] [file]\nOr:    cat file.log | netlog \n");
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
$matches = [];
$filter = null;

function render($lines, $offset, $perPage, $vendors, &$map, &$nextColorIndex, $palette, $searchTerm = null, $searchIsRegex = false) {
    system('clear');
    $end = min($offset + $perPage, count($lines));
    for ($i = $offset; $i < $end; $i++) {
        echo highlightLine($lines[$i], $vendors, $map, $nextColorIndex, $palette, $searchTerm, $searchIsRegex) . "\n";
    }
    echo "\nLines " . ($offset+1) . " - " . ($end) . " / " . count($lines) . " ";
}

function getInput($prompt) {
    echo "$prompt";
    shell_exec('stty echo');
    $term = trim(fgets(STDIN));
    shell_exec('stty -echo');
    return $term;
}

function findMatches($lines, $term, $regex = false) {
    $results = [];
    foreach ($lines as $i => $line) {
        if ($regex) {
            $pattern = "/$term/i";  // <-- Add this line
            if (@preg_match($pattern, $line)) $results[] = $i;
        } else {
            if (stripos($line, $term) !== false) $results[] = $i;
        }
    }
    return $results;
}

shell_exec('stty -icanon -echo');


//POSIX STANDARD IN BYPASS
if (!posix_isatty(STDIN)) {
    // Piped input — stream mode
    foreach ($lines as $line) {
        echo highlightLine($line, $vendors, $macColorMap, $nextColorIndex, $colorPalette) . "\n";
    }
    saveColorMap($colorFile, $macColorMap, $nextColorIndex);
    exit;
}

if ($tailMode) {
    //echo "Tail Follow Mode (starting lines: $tailLines\n";
    $lastSize = filesize($logFile);

    $lastColorReload = time();
    
    // Print the last 10 lines
    $lines = file($logFile, FILE_IGNORE_NEW_LINES);
    $lastLines = array_slice($lines, -$tailLines);
    foreach ($lastLines as $line) {
        echo highlightLine($line, $vendors, $macColorMap, $nextColorIndex, $colorPalette) . "\n";
    }

    while (true) {
        clearstatcache();
        if (time() - $lastColorReload >= 5) {
            if (file_exists($colorFile)) {
                $json = json_decode(file_get_contents($colorFile), true);
                $macColorMap = $json['map'] ?? $macColorMap;
                $nextColorIndex = $json['index'] ?? $nextColorIndex;
            }
            $lastColorReload = time();
        }
        $currentSize = filesize($logFile);

        if ($currentSize > $lastSize) {
            $fp = fopen($logFile, 'r');
            fseek($fp, $lastSize);
            while (($line = fgets($fp)) !== false) {

                $line = rtrim($line);
                $lines[] = $line;

                // 🧼 Limit memory usage
                if (count($lines) > 10000) {
                    array_shift($lines);
                }
                
                echo highlightLine(rtrim($line), $vendors, $macColorMap, $nextColorIndex, $colorPalette) . "\n";
            }
            fclose($fp);
            $lastSize = $currentSize;
        }

        usleep(200000); // 200ms
    }

    exit;
} else 
{
    render($filteredLines, $offset, $termHeight, $vendors, $macColorMap, $nextColorIndex, $colorPalette);
    drawStatusBar($searchTerm ?? 'None', $searchIsRegex, $filter);

    while (true) {
        $char = fread(STDIN, 1);

    if ($char === "\033") {
        $next1 = fread(STDIN, 1);
        if ($next1 === "[") {
            $next2 = fread(STDIN, 1);
            if ($next2 === 'A') $offset--;
            elseif ($next2 === 'B') $offset++;
            elseif ($next2 === '5') fread(STDIN, 1) && ($offset -= $termHeight);
            elseif ($next2 === '6') fread(STDIN, 1) && ($offset += $termHeight);
        }
    } elseif ($char === 'w' || $char === 'W') {
        $offset -= $termHeight;
    } elseif ($char === 's' || $char === 'S') {
        $offset += $termHeight;
    } elseif ($char === ' ') {
        $offset += $termHeight; // Spacebar scrolls one page down
    } elseif ($char === '/') {
        shell_exec('stty sane');
        $searchTerm = getInput("Search (plain text): ");
        $searchIsRegex = false;
        shell_exec('stty -icanon -echo');
        $matches = findMatches($filteredLines, $searchTerm, false);
        if (count($matches)) $offset = $matches[0];
    } elseif ($char === 'r') {
        shell_exec('stty sane');
        $searchTerm = getInput("Search (regex): ");
        $searchIsRegex = true;

        // ✅ Validate regex
        $pattern = "/$searchTerm/i";
        if (@preg_match($pattern, '') === false) {
            echo "Invalid regex pattern. Press any key to continue...";
            fread(STDIN, 1);
            $searchTerm = null;
            $searchIsRegex = false;
        } else {
            $matches = findMatches($filteredLines, $searchTerm, true);
            if (count($matches)) $offset = $matches[0];
        }

        shell_exec('stty -icanon -echo');
    } elseif ($char === 'n') {
        if ($searchTerm && count($matches)) {
            foreach ($matches as $i => $lineNum) {
                if ($lineNum > $offset) {
                    $offset = $lineNum;
                    break;
                }
            }
        }
    } elseif ($char === 'e') {
        if ($filter) {
            file_put_contents("logview_filtered_export.txt", implode("\n", $filteredLines));
        }
    } elseif ($char === 'f') {
        shell_exec('stty sane');
        $filter = getInput("Filter (prefix with r: for regex): ");
        shell_exec('stty -icanon -echo');
        if (str_starts_with($filter, 'r:')) {
            $pattern = substr($filter, 2);
            $filteredLines = array_values(array_filter($lines, fn($l) => @preg_match($pattern, $l)));
        } else {
            $filteredLines = array_values(array_filter($lines, fn($l) => stripos($l, $filter) !== false));
        }
        $offset = 0;
    } elseif ($char === 'c') {
        $filteredLines = $lines;
        $filter = null;
        $searchTerm = null;
        $searchIsRegex = false;
        $offset = 0;
    } elseif ($char === 'q') {
        break;
    }

    $offset = max(0, min($offset, max(0, count($filteredLines) - $termHeight)));
    render($filteredLines, $offset, $termHeight, $vendors, $macColorMap, $nextColorIndex, $colorPalette, $searchTerm, $searchIsRegex);
    drawStatusBar($searchTerm ?? 'None', $searchIsRegex, $filter);
    saveColorMap($colorFile, $macColorMap, $nextColorIndex);
    }
}

shell_exec('stty sane');
system('clear');
