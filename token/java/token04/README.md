# Introduction

This document describes the instructions for using the ZegoServerAssistant SDK to generate authentication tokens for accessing the ZEGO service.

# Instructions

## Importing-related

```Java
import im.zego.serverassistant.ZegoServerAssistant;
import im.zego.serverassistant.ZegoServerAssistant.TokenInfo;
```

## Room privileges description

## Error codes

```Java
enum ErrorCode {
    /**
     * Generate authentication token successfully.
     */
    SUCCESS(0),
    /**
     * Incorrect parameter `appId`.
     */
    ILLEGAL_APP_ID(1),
    /**
     * Incorrect parameter `userId`.
     */
    ILLEGAL_USER_ID(2),
    /**
     * Incorrect parameter `roomId`.
     */
    ILLEGAL_ROOM_ID(3),
    /**
     * Incorrect parameter `privilege`.
     */
    ILLEGAL_PRIVILEGE(4),
    /**
     * Incorrect parameter `expireTimeInSeconds`.
     */
    ILLEGAL_EXPIRE_TIME_IN_SECONDS(5),
    /**
     * Failed to generate authentication token.
     */
    GENERATE_TOKEN_FAILED(6);
    
    private int value;

    ErrorCode(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
```