<?php
require_once __DIR__ . '/vendor/autoload.php';

session_start();

// Your Google API credentials
$clientId = 'CLIENT-ID-HERE';
$clientSecret = 'CLIENT-SECRET-HERE';
$redirectUri = 'https://www.it-india.org/login.php'; // The URL of your script

// Create a new Google Client
$client = new Google\Client();
$client->setClientId($clientId);
$client->setClientSecret($clientSecret);
$client->setRedirectUri($redirectUri);
$client->addScope('email');
$client->addScope('profile');
?>