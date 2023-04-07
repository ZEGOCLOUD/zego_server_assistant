Package token04

Import:
- bytes
- encoding/base64
- encoding/json
- fmt
- math/rand
- time
- errors (from github.com/ZEGOCLOUD/zego_server_assistant/token/go/src/errors)
- util (from github.com/ZEGOCLOUD/zego_server_assistant/token/go/src/util)

// Definition of privilege bits
Const:
- PrivilegeKeyLogin = 1 // Whether to enable login authentication
- PrivilegeKeyPublish = 2 // Whether to enable publishing authentication

// Definition of privilege switch
Const:
- PrivilegeEnable = 1 // Enable
- PrivilegeDisable = 0 // Disable

Type TokenInfo04 struct {
    AppId   uint32 `json:"app_id"`
    UserId  string `json:"user_id"`
    CTime   int64  `json:"ctime"`
    Expire  int64  `json:"expire"`
    Nonce   int32  `json:"nonce"`
    PayLoad string `json:"payload"`
}

// Generate token for version 04
Func GenerateToken04(appId uint32, userId string, secret string, effectiveTimeInSeconds int64, payload string) (token string, err error) {
    if appId == 0 {
        return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "appId Invalid")
    }
    if userId == "" {
        return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "userId Invalid")
    }
    if len(secret) != 32 {
        return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "secret Invalid")
    }
    if effectiveTimeInSeconds <= 0 {
        return "", errors.NewZegoSDKError(errors.InvalidParamErrorCode, "effectiveTimeInSeconds Invalid")
    }

    // Set token info
    tokenInfo := TokenInfo04{
        AppId:   appId,
        UserId:  userId,
        CTime:   time.Now().Unix(),
        Expire:  0,
        Nonce:   makeNonce(),
        PayLoad: payload,
    }
    tokenInfo.Expire = tokenInfo.CTime + effectiveTimeInSeconds
    
    // Convert token info to json
    plaintText, err := json.Marshal(tokenInfo)
    if err != nil {
        return "", err
    }

    // Generate a random 16-byte string as the AES encryption vector and encode it with the ciphertext together using Base64 to generate the final token
    iv := makeRandomIv()

    // Encrypt
    cryptedBuf, err := util.AesEncrypt(plaintText, []byte(secret), iv)
    if err != nil {
        return "", fmt.Errorf("AesEncrypt error:%s, plaintText:%s, iv:%s", err.Error(), plaintText, iv)
    }

    // len+data
    resultSize := len(cryptedBuf) + 28
    result := bytes.NewBuffer(make([]byte, 0, resultSize))

    // Pack data
    err = util.PackInt64(result, tokenInfo.Expire)
    if err != nil {
        return "", fmt.Errorf("PackData1 error:%s, timeout:%d, result%s", err, tokenInfo.Expire, result)
    }
    err = util.PackString(result, string(iv))
    if err != nil {
        return "", fmt.Errorf("PackData2 error:%s, iv:%d, result%s", err, iv, result)
    }
    err = util.PackString(result, string(cryptedBuf))
    if err != nil {
        return "", fmt.Errorf("PackData3 error:%s, cryptedData:%d, result%s", err, cryptedBuf, result)
    }

    token = "04" + base64.StdEncoding.EncodeToString(result.Bytes())
    return token, nil
}

Func makeNonce() int32 {
    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    return r.Int31()
}

Func makeRandomIv() []byte {
    str := "0123456789abcdefghijklmnopqrstuvwxyz"
    bytes := []byte(str)
    result := []byte{}
    r := rand.New(rand.NewSource(time.Now().UnixNano()))
    for i := 0; i < 16; i++ {
        result = append(result, bytes[r.Intn(len(bytes))])
    }
    return result
}
