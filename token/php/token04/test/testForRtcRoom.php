<?php
require_once '../auto_loader.php';
use ZEGO\ZegoServerAssistant;
use ZEGO\ZegoErrorCodes;

//
// Authorization token generation example, contact ZEGO technical support to enable this feature before use
//


// Permission bit definition
const PrivilegeKeyLogin   = 1; // Login permission
const PrivilegeKeyPublish = 2; // Push stream permission

// Permission switch definition
const PrivilegeEnable     = 1; // Turn on
const PrivilegeDisable    = 0; // Turn off

// Please modify appID to your own appId, appid is a number
// Example: 1234567890
$appId = 1234567890;

// Please modify serverSecret to your own serverSecret, serverSecret is a string
// Example: 'fa94dd0f974cf2e293728a526b028271'
$serverSecret = '';

// Please modify userId to the user's userId, userId is a string
$userId = 'user1';

// Please modify roomId to the user's roomId, roomId is a string
$roomId = "room1";

$rtcRoomPayLoad = [
    'room_id' => $roomId, // Room ID; used to strongly verify the room ID of the interface
    'privilege' => [     // Permission bit switch list; used to strongly verify the operation permission of the interface
        PrivilegeKeyLogin => PrivilegeEnable, // Allow login
        PrivilegeKeyPublish => PrivilegeDisable, // Do not allow streaming
    ],
    'stream_id_list' => [] // Stream list; used to strongly verify the stream ID of the interface; can be empty, if it is empty, the stream ID is not verified
];

$payload = json_encode($rtcRoomPayLoad);

// 3600 is the token expiration time, in seconds
$token = ZegoServerAssistant::generateToken04($appId, $userId, $serverSecret, 3600, $payload);
if( $token->code == ZegoErrorCodes::success ){
  #...
}
print_r($token);

//demo
//3AAAAAGCKKT8AEGZvcmtpc2xieW4wdTI4cXcAoPBuvYE1pAu6k+I9aVF4ooQFkG60sNBVZd8quE2Y/lIgkr60HZT5nP1fUgYABO+wpdT7EOJi00k1oycbtpP3E4wsOgAU11gyPSkBVyJ3V4i2nma8v9IPuH5r9WOVSqsngwWDAlBVxjVO14cWyfGc3UDynsALk+qd9Rk8PVrhWTNWpqZxCsUDyk79omSC4wI4CY/wLmiM+AN+wcL9ohGUNbo=
