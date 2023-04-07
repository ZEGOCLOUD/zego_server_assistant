
const { generateToken04 } = require('../server/zegoServerAssistant');
// Please modify appID to your own appId. appid is a number.
// Example: 1234567890
const appID = ; // type: number

// Please modify serverSecret to your own serverSecret. serverSecret is a string.
// Example: 'sdfsdfsd323sdfsdf'
const serverSecret = ;// type: 32 byte length string

// Please modify userId to the user's userId.
const userId = 'user1';// type: string

const effectiveTimeInSeconds = 3600; //type: number; unit: s； token expiration time, unit: seconds
const payloadObject = {
    room_id: 'room1', // Please modify to the user's roomID
    // The token generated in this example allows loginRoom.
    // The token generated in this example does not allow publishStream.
    privilege: {
        1: 1,   // loginRoom: 1 pass , 0 not pass
        2: 0    // publishStream: 1 pass , 0 not pass
    },
    stream_id_list: null
}; // 
const payload = JSON.stringify(payloadObject);
// Build token 
const token =  generateToken04(appID, userId, serverSecret, effectiveTimeInSeconds, payload);
console.log('token:',token); // Do not modify the code.