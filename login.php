<?php
// Enable error reporting for debugging.
error_reporting(E_ALL);
ini_set('display_errors', 1);

// The path to the vendor directory is now relative to the root, pointing to the 'bdc' subdirectory.
require_once __DIR__ . '/bdc/vendor/autoload.php';
session_start();

// Google API configuration
// IMPORTANT: Replace with your actual client ID and secret.
$clientID = 'CLIENT-ID-HERE';
$clientSecret = 'CLIENT-ID-SECRET-HERE';
$redirectUri = 'https://www.yourdomainhere.com/login.php'; // This must match exactly what is in your Google Console!

$client = new Google\Client();
$client->setClientId($clientID);
$client->setClientSecret($clientSecret);
$client->setRedirectUri($redirectUri);
$client->addScope("email");
$client->addScope("profile");

// Check if a code is received from the Google API
if (isset($_GET['code'])) {
    try {
        $token = $client->fetchAccessTokenWithAuthCode($_GET['code']);
        $client->setAccessToken($token);

        // Get the user's profile information
        $google_oauth = new Google\Service\Oauth2($client);
        $google_account_info = $google_oauth->userinfo->get();

        // Store the information in the session
        $_SESSION['user_email'] = $google_account_info->email;
        $_SESSION['user_name'] = $google_account_info->name;
        $_SESSION['user_avatar'] = $google_account_info->picture;

        // Redirect to the main BDaC page inside the 'bdc' directory
        header('Location: /bdc/index.php');
        exit();
    } catch (Exception $e) {
        // Handle API errors gracefully
        echo "Authentication Error: " . htmlspecialchars($e->getMessage());
        exit();
    }
}

// Check if user is already logged in
if (isset($_SESSION['user_email'])) {
    // Redirect to the main BDaC page if already logged in
    header('Location: /bdc/index.php');
    exit();
}

// Create the Google login URL and redirect the user
$authUrl = $client->createAuthUrl();
header('Location: ' . filter_var($authUrl, FILTER_SANITIZE_URL));
exit();
?>
