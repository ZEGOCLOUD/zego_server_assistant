<?php
namespace ZEGO;

class ZegoErrorCodes{
    const success                       = 0;  // Successfully get the authentication token
    const appIDInvalid                  = 1;  // The appID parameter passed in when calling the method is incorrect
    const userIDInvalid                 = 3;  // The userID parameter passed in when calling the method is incorrect
    const secretInvalid                 = 5;  // The secret parameter passed in when calling the method is incorrect
    const effectiveTimeInSecondsInvalid = 6;  // The effectiveTimeInSeconds parameter passed in when calling the method is incorrect
}