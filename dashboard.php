<?php
session_start();

// --- SECURITY CHECK: Ensure only the administrator can access this page. ---
// IMPORTANT: Replace 'your-admin-email@example.com' with your actual Google email.
if (!isset($_SESSION['user_email']) || $_SESSION['user_email'] !== 'home.arora@gmail.com') {
    // Redirect to the login page if not the admin.
    header('Location: login.php');
    exit();
}

// Define the path for the log file
$logFile = 'abuse_log.txt';
$logContent = file_exists($logFile) ? file_get_contents($logFile) : '';

// Function to parse the log file content into a structured array
function parseLogContent($content) {
    $entries = explode("========================================================\n", $content);
    $parsedData = [];
    foreach ($entries as $entry) {
        if (trim($entry) === '') {
            continue;
        }

        $lines = explode("\n", trim($entry));
        $logEntry = [];
        $currentSection = null;

        foreach ($lines as $line) {
            if (strpos($line, 'Timestamp:') !== false) {
                $logEntry['timestamp'] = trim(str_replace('Timestamp:', '', $line));
                $currentSection = null;
            } elseif (strpos($line, 'IP Address:') !== false) {
                $logEntry['ip'] = trim(str_replace('IP Address:', '', $line));
                $currentSection = null;
            } elseif (strpos($line, 'User-Agent:') !== false) {
                $logEntry['user_agent'] = trim(str_replace('User-Agent:', '', $line));
                $currentSection = null;
            } elseif (strpos($line, 'Domains Submitted:') !== false) {
                $logEntry['submitted'] = [];
                $currentSection = 'submitted';
            } elseif (strpos($line, 'Results:') !== false) {
                $logEntry['results'] = [];
                $currentSection = 'results';
            } elseif ($currentSection === 'submitted' && strpos($line, '- ') !== false) {
                $logEntry['submitted'][] = trim(str_replace('- ', '', $line));
            } elseif ($currentSection === 'results' && strpos($line, '- ') !== false) {
                $domain_status_pair = explode(': ', trim(str_replace('- ', '', $line)), 2);
                if (count($domain_status_pair) === 2) {
                    $logEntry['results'][] = ['domain' => $domain_status_pair[0], 'status' => $domain_status_pair[1]];
                }
            }
        }
        $parsedData[] = $logEntry;
    }
    return $parsedData;
}

/**
 * Parses the User-Agent string to get the browser name.
 * A very simple and basic parser.
 *
 * @param string $userAgent The raw user agent string.
 * @return string The detected browser name.
 */
function getBrowserFromUserAgent($userAgent) {
    if (strpos($userAgent, 'Edg/') !== false) return 'Edge';
    if (strpos($userAgent, 'Chrome/') !== false) return 'Chrome';
    if (strpos($userAgent, 'Firefox/') !== false) return 'Firefox';
    if (strpos($userAgent, 'Safari/') !== false) return 'Safari';
    if (strpos($userAgent, 'OPR/') !== false) return 'Opera';
    return 'Unknown';
}

/**
 * Placeholder for Geo IP lookup. This function would require an external
 * library or API call to be fully functional. For this simple script,
 * it returns a hardcoded location based on the first octet of the IP.
 *
 * @param string $ip The IP address to look up.
 * @return string The geographical location.
 */
function getGeoIpLocation($ip) {
    // A simple, non-accurate mapping for demonstration purposes.
    $parts = explode('.', $ip);
    if (isset($parts[0])) {
        if ($parts[0] >= 1 && $parts[0] <= 49) return 'North America';
        if ($parts[0] >= 50 && $parts[0] <= 99) return 'Europe';
        if ($parts[0] >= 100 && $parts[0] <= 149) return 'Asia';
        if ($parts[0] >= 150 && $parts[0] <= 199) return 'South America';
    }
    return 'Unknown Location';
}


$dashboardData = parseLogContent($logContent);
$totalQueries = count($dashboardData);
$dailyQueries = 0;
$weeklyQueries = 0;
$monthlyQueries = 0;

$topDomains = [];
$browserUsage = [];
$geoIpLocations = [];

$today = new DateTime('today');
$startOfWeek = new DateTime('monday this week');
$startOfMonth = new DateTime('first day of this month');

foreach ($dashboardData as $entry) {
    try {
        $timestamp = new DateTime($entry['timestamp']);

        // Count daily, weekly, monthly queries
        if ($timestamp >= $today) $dailyQueries++;
        if ($timestamp >= $startOfWeek) $weeklyQueries++;
        if ($timestamp >= $startOfMonth) $monthlyQueries++;

        // Aggregate domains
        foreach ($entry['results'] as $result) {
            $domain = strtolower($result['domain']);
            $topDomains[$domain] = ($topDomains[$domain] ?? 0) + 1;
        }

        // Aggregate browser usage
        $browser = getBrowserFromUserAgent($entry['user_agent'] ?? 'Unknown');
        $browserUsage[$browser] = ($browserUsage[$browser] ?? 0) + 1;
        
        // Aggregate Geo IP locations
        $location = getGeoIpLocation($entry['ip']);
        $geoIpLocations[$location] = ($geoIpLocations[$location] ?? 0) + 1;

    } catch (Exception $e) {
        // Skip entries with invalid timestamps
        continue;
    }
}

// Sort top domains, browsers, and Geo IPs
arsort($topDomains);
arsort($browserUsage);
arsort($geoIpLocations);

// Get the top 10 domains
$topDomains = array_slice($topDomains, 0, 10);

// Reverse the log data for display, showing most recent first
$dashboardData = array_reverse($dashboardData);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BDaC Admin Dashboard</title>
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
        .table-container {
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background-color: #f7fafc;
            font-weight: 600;
        }
        tr:nth-child(even) {
            background-color: #fcfcfc;
        }
        .card {
            background-color: white;
            padding: 1.5rem;
            border-radius: 0.75rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
    </style>
</head>
<body class="bg-gray-100">

    <!-- Header -->
    <header class="bg-white shadow-md py-4 px-6 md:px-12 flex flex-col md:flex-row justify-between items-center">
        <div class="flex items-center space-x-4 mb-4 md:mb-0">
            <h1 class="text-3xl font-bold text-gray-800">BDaC Dashboard</h1>
            <nav class="flex space-x-4">
                <a href="index.php" class="text-blue-600 hover:text-blue-800 font-medium transition-colors duration-200">Home</a>
                <a href="dashboard.php" class="text-blue-600 hover:text-blue-800 font-medium transition-colors duration-200">Dashboard</a>
            </nav>
        </div>
        <div class="text-right flex items-center space-x-4">
            <a href="logout.php" class="text-sm text-blue-500 hover:text-blue-700 font-medium">Logout</a>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-grow flex items-start justify-center p-4">
        <div class="w-full max-w-7xl space-y-8">
            <h2 class="text-2xl font-bold text-gray-800">Admin Dashboard</h2>

            <!-- Analytics Summary Section -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">

                <!-- Queries Card -->
                <div class="card">
                    <h3 class="text-lg font-semibold text-gray-700 mb-2">Total Queries</h3>
                    <p class="text-4xl font-bold text-blue-600"><?= $totalQueries ?></p>
                    <div class="mt-4 text-sm text-gray-600">
                        <p>Today: <span class="font-bold"><?= $dailyQueries ?></span></p>
                        <p>This Week: <span class="font-bold"><?= $weeklyQueries ?></span></p>
                        <p>This Month: <span class="font-bold"><?= $monthlyQueries ?></span></p>
                    </div>
                </div>

                <!-- Top Queried Domains Card -->
                <div class="card">
                    <h3 class="text-lg font-semibold text-gray-700 mb-2">Top Queried Domains</h3>
                    <?php if (empty($topDomains)): ?>
                        <p class="text-sm text-gray-500">No data available.</p>
                    <?php else: ?>
                        <ul class="space-y-1">
                            <?php foreach ($topDomains as $domain => $count): ?>
                                <li class="flex justify-between text-sm text-gray-600">
                                    <span><?= htmlspecialchars($domain) ?></span>
                                    <span class="font-bold text-gray-800"><?= $count ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>

                <!-- Browser Usage Card -->
                <div class="card">
                    <h3 class="text-lg font-semibold text-gray-700 mb-2">Browser Usage</h3>
                    <?php if (empty($browserUsage)): ?>
                         <p class="text-sm text-gray-500">No data available.</p>
                    <?php else: ?>
                        <ul class="space-y-1">
                            <?php foreach ($browserUsage as $browser => $count): ?>
                                <li class="flex justify-between text-sm text-gray-600">
                                    <span><?= htmlspecialchars($browser) ?></span>
                                    <span class="font-bold text-gray-800"><?= $count ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>

                <!-- Geo IP Locations Card -->
                <div class="card">
                    <h3 class="text-lg font-semibold text-gray-700 mb-2">Geo IP Locations (Approx.)</h3>
                    <?php if (empty($geoIpLocations)): ?>
                         <p class="text-sm text-gray-500">No data available.</p>
                    <?php else: ?>
                        <ul class="space-y-1">
                            <?php foreach ($geoIpLocations as $location => $count): ?>
                                <li class="flex justify-between text-sm text-gray-600">
                                    <span><?= htmlspecialchars($location) ?></span>
                                    <span class="font-bold text-gray-800"><?= $count ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>

            </div>

            <!-- Detailed Log Table Section -->
            <div class="card mt-8">
                <h3 class="text-xl font-semibold text-gray-700 mb-4">Recent Queries Log</h3>
                <?php if (empty($dashboardData)): ?>
                    <div class="text-center text-gray-500 py-8">
                        <p>No queries have been logged yet.</p>
                    </div>
                <?php else: ?>
                    <div class="table-container rounded-lg border border-gray-200">
                        <table>
                            <thead>
                                <tr class="bg-gray-50">
                                    <th>Timestamp</th>
                                    <th>IP Address</th>
                                    <th>User Agent</th>
                                    <th>Submitted Domains</th>
                                    <th>Results</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($dashboardData as $entry): ?>
                                <tr>
                                    <td class="text-sm text-gray-600"><?= htmlspecialchars($entry['timestamp']) ?></td>
                                    <td class="text-sm text-gray-600"><?= htmlspecialchars($entry['ip']) ?></td>
                                    <td class="text-sm text-gray-600"><?= htmlspecialchars($entry['user_agent'] ?? 'N/A') ?></td>
                                    <td class="text-sm text-gray-600">
                                        <ul>
                                            <?php foreach ($entry['submitted'] as $domain): ?>
                                                <li><?= htmlspecialchars($domain) ?></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </td>
                                    <td class="text-sm text-gray-600">
                                        <ul>
                                            <?php foreach ($entry['results'] as $result): ?>
                                                <li><?= htmlspecialchars($result['domain']) . ': ' . htmlspecialchars($result['status']) ?></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
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
