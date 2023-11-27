<?php

use IPLib\Address\IPv4;
use IPLib\Address\IPv6;
use IPLib\Address\Type;
use IPLib\Factory;
use IPLib\Range\Subnet;

header("Content-Security-Policy: default-src 'none'; img-src 'self' tools-static.wmflabs.org; style-src 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style");
header("X-Frame-Options: DENY");
header("X-Xss-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");

require_once('vendor/autoload.php');
?>
<!DOCTYPE html>
<html lang="en_GB" class="h-100">
<head>
    <link rel="stylesheet" href="vendor/twbs/bootstrap/dist/css/bootstrap.css" integrity="sha256-L9fxXhh0DKyukbrb0cy4GeQxzbUQ2K8+70UQCD3i5zM=">
    <title>Rangeblock finder</title>
</head>
<body class="d-flex flex-column h-100">
    <main class="flex-shrink-0">
        <div class="container-fluid">
            <h2 class="text-center">Rangeblock finder</h2>
            <form method="post" class="mb-3">
                <div class="form-row">
                    <div class="col">
                        <label for="ipSearch" class="sr-only">IPv4 or IPv6 address</label>
                        <input class="form-control" type="text" name="ip" id="ipSearch" placeholder="IPv4 or IPv6 address" <?= isset($_REQUEST['ip']) ? 'value="' . $_REQUEST['ip'] . '"' : ''?>/>
                    </div>
                    <div class="col-auto">
                        <button class="btn btn-primary" type="submit">Search</button>
                    </div>
                </div>
                <div class="form-row">
                    <div class="col"></div>
                    <div class="col-auto">
                        <div class="custom-control custom-switch">
                            <input type="checkbox" class="custom-control-input" id="excludeLow" name="excludelow" <?= isset($_REQUEST['excludelow']) ? 'checked="checked"' : ''?>>
                            <label class="custom-control-label" for="excludeLow">Exclude small v6 CIDR ranges</label>
                        </div>
                    </div>
                </div>
            </form>
<?php
function writeFooter() {
    ?>
        </div>
    </main>
    <footer class="footer mt-auto py-3">
        <div class="container-fluid">
            <span class="text-muted">IP rangeblock finder tool. <a href="https://phabricator.wikimedia.org/source/tool-rangeblockfinder/">Source</a> / <a href="https://phabricator.wikimedia.org/project/board/5049/">Issues</a> / <a href="https://opensource.org/licenses/mit-license.php">Licence</a></span>
        </div>
    </footer>
    </body>
    </html>
    <?php
}

if(!isset($_REQUEST['ip'])) {
    writeFooter();
    die();
}

$cookieJar = tempnam("/tmp", "CURLCOOKIE");
$curlOpt = array(
    CURLOPT_COOKIEFILE => $cookieJar,
    CURLOPT_COOKIEJAR => $cookieJar,
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_USERAGENT => 'RangeblockFinder/0.1 (+mailto:wikimedia@stwalkerster.co.uk)',

);

const API_ENWIKI = 'https://en.wikipedia.org/w/api.php';
const API_METAWIKI = 'https://meta.wikimedia.org/w/api.php';

function apiQuery($base, array $params, array $substitutions, $post = false)
{
    global $curlOpt;

    $usableParams = [];

    foreach ($params as $k => $v) {
        $val = $v;

        foreach ($substitutions as $kid => $repl) {
            $val = str_replace('{' . $kid . '}', $repl, $val);
        }

        $usableParams[$k] = $val;
    }

    $usableParams['format'] = 'json';

    $queryString = http_build_query($usableParams);

    $url = $base;

    if (!$post) {
        $url .= '?' . $queryString;
    }

    $ch = curl_init();
    curl_setopt_array($ch, $curlOpt);
    curl_setopt($ch, CURLOPT_URL, $url);

    if ($post) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $queryString);
    }

    $data = curl_exec($ch);

    if (curl_errno($ch)) {
        die('cURL Error: ' . curl_error($ch));
    }

    return json_decode($data);
}

function countBlocks($target) {
  $enwikiGeneralQuery = [
      'action' => 'query',
      'list' => 'logevents',
      'letitle' => 'User:{0}',
      'letype' => 'block',
  ];

  $data = apiQuery(API_ENWIKI, $enwikiGeneralQuery, [$target]);
  return count($data->query->logevents);
}
function countGlobalBlocks($target) {
  $metaGeneralQuery = [
      'action' => 'query',
      'list' => 'logevents',
      'letitle' => 'User:{0}',
      'letype' => 'gblblock',
  ];

  $data = apiQuery(API_METAWIKI, $metaGeneralQuery, [$target]);
  return count($data->query->logevents);
}

$address = Factory::addressFromString($_REQUEST['ip']);
$excludeLowV6 = isset($_REQUEST['excludelow']);

$ipBlocks = countBlocks($address->toString());
$ipGBlocks = countGlobalBlocks($address->toString());

?>
<table class="table table-sm table-striped">
    <thead><tr><th>Target</th><th>CIDR</th><th>Upper bound of range</th><th>Local block count</th><th></th><th>Global block count</th><th></th></tr></thead>
    <tbody>
        <tr>
            <td><code><?= $address->toString() ?></code></td>
            <td></td>
            <td></td>
            <td class="<?= $ipBlocks > 0 ? "bg-danger text-white" : "" ?>"><?= $ipBlocks ?></td>
            <td><a href="https://en.wikipedia.org/w/index.php?title=Special%3ALog&type=block&page=User%3A<?= urlencode($address->toString()) ?>">Local log</a>
            <td class="<?= $ipGBlocks > 0 ? "bg-danger text-white" : "" ?>"><?= $ipGBlocks ?></td>
            <td><a href="https://meta.wikimedia.org/w/index.php?title=Special:Log&type=gblblock&page=<?= urlencode($address->toString()) ?>">Global log</a>
        </tr>
<?php

function writeTableRow($cidr, $lowerBound, $upperBound, $ipBlocks, $ipGBlocks) {
?>
    <tr>
        <td><code><?= $lowerBound ?></code></td>
        <td>/<?= $cidr ?></td>
        <td><code><?= $upperBound ?></code></td>
        <td class="<?= $ipBlocks > 0 ? "bg-danger text-white" : "" ?>"><?= $ipBlocks ?></td>
        <td><a href="https://en.wikipedia.org/w/index.php?title=Special%3ALog&type=block&page=User%3A<?= urlencode($lowerBound . "/" . $cidr) ?>">Local log</a>
        <td class="<?= $ipGBlocks > 0 ? "bg-danger text-white" : "" ?>"><?= $ipGBlocks ?></td>
        <td><a href="https://meta.wikimedia.org/w/index.php?title=Special:Log&type=gblblock&page=<?= urlencode($lowerBound . "/" . $cidr) ?>">Global log</a>
    </tr>
<?php
}

if($address->getAddressType() == Type::T_IPv4) {
    /** @var IPv4 $v4Address */
    $v4Address = $address;

    for($x = 32; $x >= 16; --$x) {
        $range = Subnet::fromString($v4Address->toString() . "/${x}");
        $ipBlocks = countBlocks($range);
        $ipGBlocks = countGlobalBlocks($range);

        writeTableRow($x, $range->getStartAddress(), $range->getEndAddress(), $ipBlocks, $ipGBlocks);
    }
} else if($address->getAddressType() == Type::T_IPv6) {
    /** @var IPv6 $v6Address */
    $v6Address = $address;

    global $excludeLowV6;
    $lowerBound = 128;

    if($excludeLowV6) {
        $lowerBound = 64;

        // manually re-add 128.
        $range = Subnet::fromString($v6Address->toString() . "/128");
        $ipBlocks = countBlocks($range);
        $ipGBlocks = countGlobalBlocks($range);

        writeTableRow(128, $range->getStartAddress(), $range->getEndAddress(), $ipBlocks, $ipGBlocks);

        ?><tr>
        <td colspan="7" class="text-muted text-center"><em>Checking low CIDR prefixes skipped. To re-run the check for all CIDR prefixes, <a href="?ip=<?= urlencode($_REQUEST['ip']) ?>">click here</a></em></td>
        </tr><?php
    }

    for($x = $lowerBound; $x >= 19; --$x) {
        $range = Subnet::fromString($v6Address->toString() . "/${x}");
        $ipBlocks = countBlocks($range);
        $ipGBlocks = countGlobalBlocks($range);

        writeTableRow($x, $range->getStartAddress(), $range->getEndAddress(), $ipBlocks, $ipGBlocks);
    }
}

?>
    </tbody>
</table>
<?php
writeFooter();
