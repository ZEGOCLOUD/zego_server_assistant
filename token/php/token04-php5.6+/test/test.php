<?php
require_once '../auto_loader.php';
use ZEGO\ZegoServerAssistant;
use ZEGO\ZegoErrorCodes;

//
// Basic authentication token generation example
//

// Please modify appID to your own appId, appid is a number
// Example: 1234567890
$appId = 1234567890;

// Please modify serverSecret to your own serverSecret, serverSecret is a string
// Example: 'fa94dd0f974cf2e293728a526b028271'
$serverSecret = '';

// Please modify userId to the user's userId
$userId = 'user1';

// When generating a basic authentication token, the payload should be set to an empty string
$payload = '';

// 3600 is the expiration time of the token, in seconds
$token = ZegoServerAssistant::generateToken04($appId, $userId, $serverSecret, 3600, $payload);
if ($token->code == ZegoErrorCodes::success) {
  # ...
}
print_r($token);

//demo
//3AAAAAGCKKT8AEGZvcmtpc2xieW4wdTI4cXcAoPBuvYE1pAu6k+I9aVF4ooQFkG60sNBVZd8quE2Y/lIgkr60HZT5nP1fUgYABO+wpdT7EOJi00k1oycbtpP3E4wsOgAU11gyPSkBVyJ3V4i2nma8v9IPuH5r9WOVSqsngwWDAlBVxjVO14cWyfGc3UDynsALk+qd9Rk8PVrhWTNWpqZxCsUDyk79omSC4wI4CY/wLmiM+AN+wcL9ohGUNbo=
