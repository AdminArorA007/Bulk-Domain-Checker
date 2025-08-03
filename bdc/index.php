<?php
require_once __DIR__ . '/vendor/autoload.php';
session_start();

// --- Security and Feature Constants ---
// Maximum domains a non-logged-in user can check before being forced to log in.
define('LOGIN_THRESHOLD', 100);
// Number of domains a non-logged-in user can check before the CAPTCHA is required.
define('CAPTCHA_THRESHOLD', 10);
// Rate limit: one request per 10 seconds.
define('RATE_LIMIT_SECONDS', 10);

// --- Session and IP Tracking Logic ---
// Initialize session variables if they don't exist
if (!isset($_SESSION['domains_checked'])) {
    $_SESSION['domains_checked'] = 0;
    $_SESSION['checked_results'] = ['available' => [], 'taken' => [], 'other' => []];
}
if (!isset($_SESSION['ip_usage'])) {
    $_SESSION['ip_usage'] = [];
}

$clientIp = $_SERVER['REMOTE_ADDR'];

/**
 * Logs the domain check query and results to a file for abuse tracking.
 *
 * @param string $ip The client's IP address.
 * @param array $domains The list of domains submitted for checking.
 * @param array $results The results of the domain check.
 */
function logQuery($ip, $domains, $results) {
    // Define the path for the log file
    $logFile = 'abuse_log.txt';
    
    // Create a log entry string
    $logEntry = "========================================================\n";
    $logEntry .= "Timestamp: " . date('Y-m-d H:i:s') . "\n";
    $logEntry .= "IP Address: " . $ip . "\n";
    $logEntry .= "Domains Submitted:\n";
    $logEntry .= implode("\n", array_map(function($domain) { return "  - " . $domain; }, $domains)) . "\n";
    $logEntry .= "Results:\n";
    
    foreach ($results as $item) {
        $logEntry .= "  - " . $item['domain'] . ": " . $item['status'] . "\n";
    }
    
    // Append the log entry to the file
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
}

// Function to generate a simple math CAPTCHA
function generateCaptcha() {
    $num1 = rand(1, 9);
    $num2 = rand(1, 9);
    $_SESSION['captcha_answer'] = $num1 + $num2;
    return "What is " . $num1 . " + " . $num2 . "?";
}

/**
 * Checks domain availability using a WHOIS lookup.
 * This is more reliable than a simple gethostbyname() check.
 *
 * @param string $domain The domain name to check.
 * @return string The availability status ('✅ Available' or '❌ Taken').
 */
function checkDomainAvailability($domain) {
    $domain = trim($domain);
    $domain = str_replace('www.', '', $domain);
    if (empty($domain)) {
        return null;
    }

    $tld = pathinfo($domain, PATHINFO_EXTENSION);
    $whoisServers = [
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.publicinterestregistry.net',
        'info' => 'whois.afilias.net',
        'biz' => 'whois.nic.biz',
        'co' => 'whois.nic.co',
        'us' => 'whois.nic.us',
        'in' => 'whois.inregistry.net',
        // Add more TLDs and WHOIS servers as needed
    ];

    if (!isset($whoisServers[$tld])) {
        return '❓ Unchecked (TLD not supported)';
    }

    $whoisServer = $whoisServers[$tld];
    $isAvailable = false;
    $result = '';

    $fp = @fsockopen($whoisServer, 43, $errno, $errstr, 5);
    if ($fp) {
        fputs($fp, $domain . "\r\n");
        while (!feof($fp)) {
            $result .= fgets($fp);
        }
        fclose($fp);

        $not_found_strings = [
            'No match for', 'NOT FOUND', 'No Data Found', 'Domain not found',
            'is available for registration', 'No entries found', 'Status: AVAILABLE'
        ];

        foreach ($not_found_strings as $str) {
            if (stripos($result, $str) !== false) {
                $isAvailable = true;
                break;
            }
        }
    } else {
        return '⚠️ Error connecting to WHOIS server';
    }

    return $isAvailable ? '✅ Available' : '❌ Taken';
}

$errorMessage = '';
$captchaQuestion = generateCaptcha();

// Handle download request
if (isset($_GET['download']) && !empty($_SESSION['checked_results'])) {
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="bdac_results_' . date('Y-m-d') . '.txt"');

    echo "--- Available Domains ---\n";
    foreach ($_SESSION['checked_results']['available'] as $domain) {
        echo $domain . "\n";
    }

    echo "\n--- Unavailable Domains ---\n";
    foreach ($_SESSION['checked_results']['taken'] as $domain) {
        echo $domain . "\n";
    }

    echo "\n--- Other Statuses ---\n";
    foreach ($_SESSION['checked_results']['other'] as $item) {
        echo $item['domain'] . ": " . $item['status'] . "\n";
    }

    exit();
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['domains'])) {
    // Check if the user is authenticated and if they have hit the unauthenticated limit
    $isAuthenticated = isset($_SESSION['user_email']);
    if (!$isAuthenticated && $_SESSION['domains_checked'] >= LOGIN_THRESHOLD) {
        header('Location: /login.php');
        exit();
    }

    // --- Rate Limiting Check (by IP) ---
    $lastCheckTime = isset($_SESSION['ip_usage'][$clientIp]) ? $_SESSION['ip_usage'][$clientIp] : 0;
    $timeSinceLastCheck = time() - $lastCheckTime;
    if ($timeSinceLastCheck < RATE_LIMIT_SECONDS) {
        $errorMessage = 'Please wait ' . (RATE_LIMIT_SECONDS - $timeSinceLastCheck) . ' seconds before checking again.';
    }

    // --- CAPTCHA Check (Conditional) ---
    if (empty($errorMessage) && !$isAuthenticated && $_SESSION['domains_checked'] >= CAPTCHA_THRESHOLD) {
        if (!isset($_POST['captcha']) || (int)$_POST['captcha'] !== $_SESSION['captcha_answer']) {
            $errorMessage = 'Incorrect CAPTCHA answer. Please try again.';
            $captchaQuestion = generateCaptcha();
        }
    }

    // --- Process domains if no errors ---
    if (empty($errorMessage)) {
        $_SESSION['ip_usage'][$clientIp] = time(); // Update IP usage time

        $domains = explode("\n", $_POST['domains']);
        $results = [];
        $domainsProcessedCount = 0;

        foreach ($domains as $domain) {
            $domain = trim($domain);
            if ($domain) {
                // Basic input validation with a regex
                if (preg_match('/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z]{2,})+$/i', $domain)) {
                    $status = checkDomainAvailability($domain);
                    if ($status !== null) {
                        $results[] = ['domain' => $domain, 'status' => $status];
                        $domainsProcessedCount++;
                        // Store the results for the summary
                        if ($status === '✅ Available') {
                            $_SESSION['checked_results']['available'][] = $domain;
                        } elseif ($status === '❌ Taken') {
                            $_SESSION['checked_results']['taken'][] = $domain;
                        } else {
                            $_SESSION['checked_results']['other'][] = ['domain' => $domain, 'status' => $status];
                        }
                    }
                } else {
                    $results[] = ['domain' => $domain, 'status' => '❌ Invalid domain format'];
                }
            }
        }
        
        // Update the total domains checked for the current session
        if (!$isAuthenticated) {
             $_SESSION['domains_checked'] += $domainsProcessedCount;
        }

        // Call the logging function with the collected data
        logQuery($clientIp, $domains, $results);

        // Regenerate CAPTCHA for the next request
        $captchaQuestion = generateCaptcha();
    }
}

$isLoggedIn = isset($_SESSION['user_email']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bulk Domain Availability Checker</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body {
            font-family: 'Inter', sans-serif;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        main {
            flex-grow: 1;
        }
        ul {
            list-style: none;
            padding: 0;
            margin-top: 1rem;
        }
        ul li {
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
            border-radius: 0.5rem;
            background-color: #f7fafc;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body class="bg-gray-100">

    <!-- Header -->
    <header class="bg-white shadow-md py-4 px-6 md:px-12 flex flex-col md:flex-row justify-between items-center">
        <div class="flex items-center space-x-4 mb-4 md:mb-0">
            <h1 class="text-3xl font-bold text-gray-800">BDaC</h1>
            <nav class="flex space-x-4">
                <a href="/bdc/index.php" class="text-blue-600 hover:text-blue-800 font-medium transition-colors duration-200">Home</a>
                <a href="/bdc/dashboard.php" class="text-blue-600 hover:text-blue-800 font-medium transition-colors duration-200">Dashboard</a>
            </nav>
        </div>
        <div class="text-right flex items-center space-x-4">
            <?php if ($isLoggedIn): ?>
                <?php 
                    $userName = isset($_SESSION['user_name']) ? htmlspecialchars($_SESSION['user_name']) : 'User';
                    $userAvatar = isset($_SESSION['user_avatar']) ? htmlspecialchars($_SESSION['user_avatar']) : 'https://placehold.co/40x40/E2E8F0/A0AEC0?text=👤';
                ?>
                <div class="flex items-center space-x-2">
                    <img src="<?= $userAvatar ?>" alt="User Avatar" class="h-8 w-8 rounded-full">
                    <p class="text-sm text-gray-500">Welcome, <span class="font-semibold text-gray-700"><?= $userName ?></span>!</p>
                </div>
                <a href="/logout.php" class="text-sm text-blue-500 hover:text-blue-700 font-medium">Logout</a>
            <?php else: ?>
                <p class="text-sm text-gray-500">Domains checked: <span class="font-semibold text-gray-700"><?= $_SESSION['domains_checked'] ?> / <?= LOGIN_THRESHOLD ?></span></p>
                <a href="/login.php" class="text-sm text-blue-500 hover:text-blue-700 font-medium">Login to continue</a>
            <?php endif; ?>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-grow flex items-center justify-center p-4">
        <div class="bg-white p-8 rounded-xl shadow-lg w-full max-w-lg space-y-6">

            <!-- Domain Input Form -->
            <h3 class="text-xl font-semibold text-gray-700">Enter domains here, one per line</h3>
            
            <?php if (!empty($errorMessage)): ?>
                <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-md relative" role="alert">
                    <span class="block sm:inline"><?= htmlspecialchars($errorMessage) ?></span>
                </div>
            <?php endif; ?>

            <form method="post" class="space-y-4">
                <textarea name="domains" rows="10" class="w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500" placeholder="example.com&#10;anotherdomain.net"></textarea>

                <?php if (!$isLoggedIn && $_SESSION['domains_checked'] >= CAPTCHA_THRESHOLD): ?>
                    <!-- Conditional CAPTCHA Section -->
                    <div>
                        <label class="block text-gray-700 font-semibold mb-2"><?= htmlspecialchars($captchaQuestion) ?></label>
                        <input type="number" name="captcha" required class="w-full p-3 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500" placeholder="Enter your answer">
                    </div>
                <?php endif; ?>

                <button type="submit" class="w-full bg-blue-600 text-white font-bold py-3 px-4 rounded-md shadow hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-150 ease-in-out">
                    Check Availability
                </button>
            </form>

            <!-- Results Section -->
            <?php if (isset($results) && !empty($results)): ?>
                <div class='mt-8 pt-4 border-t border-gray-200'>
                    <h3 class='text-xl font-semibold text-gray-700'>Results:</h3>
                    <ul>
                        <?php foreach ($results as $item): ?>
                            <?php
                                $status_class = ($item['status'] === '✅ Available') ? 'bg-green-50' : 'bg-red-50';
                            ?>
                            <li class='<?= $status_class ?>'>
                                <span><?= htmlspecialchars($item['domain']) ?></span>
                                <span><?= htmlspecialchars($item['status']) ?></span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            
            <!-- Summary Section with Download Button -->
            <?php if (!empty($_SESSION['checked_results']['available']) || !empty($_SESSION['checked_results']['taken']) || !empty($_SESSION['checked_results']['other'])): ?>
                <div class='mt-8 pt-4 border-t border-gray-200'>
                    <h3 class='text-xl font-semibold text-gray-700 mb-4'>Summary of All Checks</h3>
                    
                    <?php if (!empty($_SESSION['checked_results']['available'])): ?>
                        <p class="text-lg font-semibold text-gray-700">Available: (<?= count($_SESSION['checked_results']['available']) ?>)</p>
                        <ul class="mb-4">
                            <?php foreach ($_SESSION['checked_results']['available'] as $domain): ?>
                                <li class="bg-green-50"><span><?= htmlspecialchars($domain) ?></span></li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>

                    <?php if (!empty($_SESSION['checked_results']['taken'])): ?>
                        <p class="text-lg font-semibold text-gray-700">Taken: (<?= count($_SESSION['checked_results']['taken']) ?>)</p>
                        <ul class="mb-4">
                            <?php foreach ($_SESSION['checked_results']['taken'] as $domain): ?>
                                <li class="bg-red-50"><span><?= htmlspecialchars($domain) ?></span></li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                    
                    <?php if (!empty($_SESSION['checked_results']['other'])): ?>
                        <p class="text-lg font-semibold text-gray-700">Other: (<?= count($_SESSION['checked_results']['other']) ?>)</p>
                        <ul class="mb-4">
                            <?php foreach ($_SESSION['checked_results']['other'] as $item): ?>
                                <li class="bg-yellow-50"><span><?= htmlspecialchars($item['domain']) ?></span><span><?= htmlspecialchars($item['status']) ?></span></li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>

                    <a href="?download=true" class="w-full inline-block text-center bg-gray-500 text-white font-bold py-3 px-4 rounded-md shadow hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition duration-150 ease-in-out">
                        Download Results (.txt)
                    </a>
                </div>
            <?php endif; ?>

        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-gray-800 text-white py-4 px-6 md:px-12 mt-auto">
        <div class="container mx-auto text-center">
            <p>&copy; 2025 Bulk Domain Availability Checker. All rights reserved.</p>
        </div>
    </footer>

</body>
</html>
