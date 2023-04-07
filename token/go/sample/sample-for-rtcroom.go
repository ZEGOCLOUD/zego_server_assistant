package main

import (
    "encoding/json"
    "fmt"
    "github.com/ZEGOCLOUD/zego_server_assistant/token/go/src/token04"
)

/*
Example code for generating authorization tokens. This function must be enabled by contacting ZEGO technical support before use.
*/

// Token business expansion: authorization attribute
type RtcRoomPayLoad struct {
    RoomId       string      `json:"room_id"`        // Room ID; used for strong verification of the room ID of the interface
    Privilege    map[int]int `json:"privilege"`      // Permission switch list; used for strong verification of operation permissions of the interface
    StreamIdList []string    `json:"stream_id_list"` // Stream list; used for strong verification of the stream ID of the interface; can be empty; if empty, no stream ID verification is performed
}

func main() {
    // Please modify the appId to your own appId, which is a number obtained from the ZEGO console.
    // For example: 1234567890
    var appId uint32 = 1234567890

    // Please modify the serverSecret to your own serverSecret, which is a string obtained from the ZEGO console.
    // For example: "fa94dd0f974cf2e293728a526b028271"
    serverSecret := ""

    // Please modify the userId to the user's user_id
    userId := "user1"

    // Please modify the roomId to the user's roomId
    roomId := "room1"

    // The effective time of the token, in seconds
    var effectiveTimeInSeconds int64 = 3600

    // Please refer to github.com/ZEGOCLOUD/zego_server_assistant/token/go/src/token04/token04.go for definitions
    //// Permission bit definition
    //const (
    //  PrivilegeKeyLogin   = 1 // 1 represents login permission
    //  PrivilegeKeyPublish = 2 // 2 represents push stream permission
    //)

    //// Permission switch definition
    //const (
    //  PrivilegeEnable     = 1 // Allow corresponding business permission
    //  PrivilegeDisable    = 0 // Do not allow corresponding business permission
    //)

    // Business permission authentication configuration, multiple permission bits can be configured
    privilege := make(map[int]int)
    privilege[token04.PrivilegeKeyLogin] = token04.PrivilegeEnable    // Allow room login
    privilege[token04.PrivilegeKeyPublish] = token04.PrivilegeDisable // Do not allow streaming

    // Token business expansion configuration
    payloadData := &RtcRoomPayLoad{
        RoomId:       roomId,
        Privilege:    privilege,
        StreamIdList: nil,
    }

    payload, err := json.Marshal(payloadData)
    if err != nil {
        fmt.Println(err)
        return
    }

    // Generate token
    token, err := token04.GenerateToken04(appId, userId, serverSecret, effectiveTimeInSeconds, string(payload))
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println(token)
}