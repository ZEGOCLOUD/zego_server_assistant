/**
 * Example of generating basic authentication token.
 */

const { generateToken04 } = require('../server/zegoServerAssistant');

// Please modify appID to your own appId. appid is a number.
// Example: 1234567890
const appID = ; // type: number

// Please modify serverSecret to your own serverSecret. serverSecret is a string.
// Example: 'sdfsdfsd323sdfsdf'
const serverSecret = ;// type: 32 byte length string

// Please modify userId to the user's userId.
const userId = 'user1';// type: string

const effectiveTimeInSeconds = 3600; //type: number; unit: s; expiration time of token, in seconds.

// When generating a basic authentication token, the payload should be set to an empty string.
const payload = ''; 
// Build token 
const token =  generateToken04(appID, userId, serverSecret, effectiveTimeInSeconds, payload);
console.log('token:',token);
