/**
 * Example of generating basic authentication token
 */
const { generateToken04 } = require('../server/zegoServerAssistant');

// Please modify the appID to your own appId, appid is a number
// For example: 1234567890
const appID = ; // type: number

// Please modify the serverSecret to your own serverSecret, serverSecret is a string
// For example: 'sdfsdfsd323sdfsdf'
const serverSecret = ;// type: 32 byte length string

// Please modify the userId to the user's user_id
const userId = 'user1';// type: string

const effectiveTimeInSeconds = 3600; //type: number; unit: s; token expiration time, in seconds

// When generating the basic authentication token, the payload needs to be set to an empty string
const payload = ''; 
// Build token 
const token =  generateToken04(appID, userId, serverSecret, effectiveTimeInSeconds, payload);
console.log('token:',token);
