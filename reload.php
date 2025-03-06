<?php
header('Content-Type: application/json');

$dbHost = getenv('DB_HOST');
$dbUser = getenv('DB_USER');
$dbPass = getenv('DB_PASS');
$dbName = getenv('DB_NAME');

function getVisitorIPs() {
    $ipv4 = null;
    $ipv6 = null;

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwardedIps = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        foreach ($forwardedIps as $ip) {
            $ip = trim($ip);
            if (!$ipv4 && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ipv4 = $ip;
            } elseif (!$ipv6 && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6 = $ip;
            }
        }
    }

    if (!$ipv4 && filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ipv4 = $_SERVER['HTTP_CLIENT_IP'];
    }

    if (!$ipv6 && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $ipv6 = $_SERVER['REMOTE_ADDR'];
    } elseif (!$ipv4 && filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ipv4 = $_SERVER['REMOTE_ADDR'];
    }

    return [
        'ipv4' => $ipv4 ?: null, 
        'ipv6' => $ipv6 ?: null
    ];
}

function getIPDetails($ip) {
    $accessToken = '7c82be91a4f866';
    $url = "https://ipinfo.io/$ip?token=$accessToken";
    $response = file_get_contents($url);
    return $response ? json_decode($response, true) : null;
}

function getUserAgentDetails() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    if (strpos($userAgent, 'Firefox') !== false) {
        $browser = 'Firefox';
    } elseif (strpos($userAgent, 'Chrome') !== false && strpos($userAgent, 'Edg') === false) {
        $browser = 'Chrome';
    } elseif (strpos($userAgent, 'Safari') !== false && strpos($userAgent, 'Chrome') === false) {
        $browser = 'Safari';
    } elseif (strpos($userAgent, 'Edge') !== false) {
        $browser = 'Edge';
    } elseif (strpos($userAgent, 'Opera') !== false || strpos($userAgent, 'OPR') !== false) {
        $browser = 'Opera';
    } else {
        $browser = 'Unknown';
    }

    if (strpos($userAgent, 'Windows') !== false) {
        $os = 'Windows';
    } elseif (strpos($userAgent, 'Macintosh') !== false || strpos($userAgent, 'Mac OS X') !== false) {
        $os = 'macOS';
    } elseif (strpos($userAgent, 'Linux') !== false) {
        $os = 'Linux';
    } elseif (strpos($userAgent, 'Android') !== false) {
        $os = 'Android';
    } elseif (strpos($userAgent, 'iPhone') !== false || strpos($userAgent, 'iPad') !== false) {
        $os = 'iOS';
    } else {
        $os = 'Unknown';
    }

    if (strpos($userAgent, 'Mobi') !== false || strpos($userAgent, 'Android') !== false || strpos($userAgent, 'iPhone') !== false) {
        $device = 'Mobile';
    } elseif (strpos($userAgent, 'Tablet') !== false || strpos($userAgent, 'iPad') !== false) {
        $device = 'Tablet';
    } else {
        $device = 'Desktop';
    }

    preg_match('/\((.*?)\)/', $userAgent, $matches);
    $platformVersion = $matches[1] ?? 'Unknown';

    return [
        'browser' => $browser,
        'os' => $os,
        'device' => $device,
        'platform_version' => $platformVersion,
        'user_agent' => $userAgent
    ];
}

function saveToDatabase($ipv4, $ipv6, $ipv4Details, $ipv6Details, $userAgentDetails) {
    global $dbHost, $dbUser, $dbPass, $dbName;

    $conn = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
    if ($conn->connect_error) return false;

    $country = $ipv4Details['country'] ?? $ipv6Details['country'] ?? 'Unknown';
    $region = $ipv4Details['region'] ?? $ipv6Details['region'] ?? 'Unknown';
    $city = $ipv4Details['city'] ?? $ipv6Details['city'] ?? 'Unknown';
    $isp = $ipv4Details['org'] ?? $ipv6Details['org'] ?? 'Unknown';
    $browser = $userAgentDetails['browser'];
    $os = $userAgentDetails['os'];
    $device = $userAgentDetails['device'];
    $platformVersion = $userAgentDetails['platform_version'];
    $userAgent = $userAgentDetails['user_agent'];

    $stmt = $conn->prepare("SELECT id FROM click_logs WHERE ipv4 = ? OR ipv6 = ?");
    $stmt->bind_param("ss", $ipv4, $ipv6);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->close();
        $conn->close();
        return false;
    }

    $stmt = $conn->prepare("INSERT INTO click_logs (ipv4, ipv6, country, region, city, isp, browser, os, device, platform_version, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssssssss", $ipv4, $ipv6, $country, $region, $city, $isp, $browser, $os, $device, $platformVersion, $userAgent);
    $stmt->execute();
    $stmt->close();
    $conn->close();

    return true;
}

function sendDataToDiscord($ipv4, $ipv6, $ipv4Details, $ipv6Details, $userAgentDetails) {
    $url = "https://railway.aryanpotdar.com/send-ip";
    $data = [
        'ipv4' => $ipv4,
        'ipv6' => $ipv6,
        'ipv4_details' => $ipv4Details,
        'ipv6_details' => $ipv6Details,
        'browser' => $userAgentDetails['browser'],
        'os' => $userAgentDetails['os'],
        'device' => $userAgentDetails['device'],
        'platform_version' => $userAgentDetails['platform_version'],
        'user_agent' => $userAgentDetails['user_agent'],
        'channel_id' => "1346977028087353364"
    ];
    
    $options = [
        'http' => [
            'header'  => "Content-type: application/json\r\n",
            'method'  => 'POST',
            'content' => json_encode($data),
        ],
    ];
    
    $context = stream_context_create($options);
    return file_get_contents($url, false, $context) !== FALSE;
}

$visitorIPs = getVisitorIPs();
$ipv4 = $visitorIPs['ipv4'];
$ipv6 = $visitorIPs['ipv6'];

$ipv4Details = $ipv4 ? getIPDetails($ipv4) : null;
$ipv6Details = $ipv6 ? getIPDetails($ipv6) : null;

$userAgentDetails = getUserAgentDetails();

if ($ipv4 || $ipv6) {
    saveToDatabase($ipv4, $ipv6, $ipv4Details, $ipv6Details, $userAgentDetails);
}

if ($ipv4 || $ipv6) {
    sendDataToDiscord($ipv4, $ipv6, $ipv4Details, $ipv6Details, $userAgentDetails);
}

echo json_encode([
    'status' => 'success',
    'ipv4' => $ipv4,
    'ipv6' => $ipv6,
    'browser' => $userAgentDetails['browser'],
    'os' => $userAgentDetails['os'],
    'device' => $userAgentDetails['device'],
    'platform_version' => $userAgentDetails['platform_version'],
    'user_agent' => $userAgentDetails['user_agent']
]);
?>