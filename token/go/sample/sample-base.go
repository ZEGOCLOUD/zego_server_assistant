package main

import (
    "fmt"
    "github.com/ZEGOCLOUD/zego_server_assistant/token/go/src/token04"
)

/*
Example code for generating basic authentication tokens
*/

func main() {
    // Please modify the appId to your own appId, which is a number obtained from the ZEGO console.
    // For example: 1234567890
    var appId uint32 = 1234567890

    // Please modify serverSecret to your own serverSecret, which is a string obtained from the ZEGO console.
    // For example: "fa94dd0f974cf2e293728a526b028271"
    serverSecret := ""

    // Please modify userId to the user's user_id.
    userId := "user1"

    // The validity period of the token, in seconds.
    var effectiveTimeInSeconds int64 = 3600
    // Token business authentication extension, leave it blank for basic authentication token.
    var payload string = ""

    // Generate the token.
    token, err := token04.GenerateToken04(appId, userId, serverSecret, effectiveTimeInSeconds, payload)
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(token)
}