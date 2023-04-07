#ifndef __ZegoServerAssistantDefines__
#define __ZegoServerAssistantDefines__

#ifdef WIN32
#ifdef ZEGO_EXPORTS
#define ZEGOSA_API __declspec(dllexport)
#define ZEGOSACALL __cdecl
#else
#define ZEGOSA_API __declspec(dllimport)
#define ZEGOSACALL __cdecl
#endif
#else
#define ZEGOSA_API __attribute__((visibility("default")))
#define ZEGOSACALL
#endif

#include <string>

namespace ZEGO
{
namespace SERVER_ASSISTANT
{

    /**
     *  The value of "key" in privilege
     *
     */
    enum kPrivilege
    {
        kPrivilegeLogin = 1,   // "key" in privilege for whether to allow login to the room; corresponding "value" in map: 0 not allowed, 1 allowed
        kPrivilegePublish = 2  // "key" in privilege for whether to allow streaming; corresponding "value" in map: 0 not allowed, 1 allowed
    };

    /**
     *  ZegoServerAssistant error code
     *
     */
    enum ErrorCode
    {
        success                       = 0,  // Successfully obtained authentication token
        appIDInvalid                  = 1,  // Error in appID parameter passed when calling method
        userIDInvalid                 = 3,  // Error in userID parameter passed when calling method
        secretInvalid                 = 5,  // Error in secret parameter passed when calling method
        effectiveTimeInSecondsInvalid = 6   // Error in effectiveTimeInSeconds parameter passed when calling method
    };

    /**
     *  Error code and its description
     *
     */
    struct ErrorInfo {
        ErrorCode   errorCode;     // Error code from ErrorCode
        std::string errorMessage;  // Detailed description of the error code
    };

    /**
     *  Return value obtained when calling GenerateToken method
     *  token: The calculated token
     *  errorInfo: Error information. When errorInfo.errorCode is 0, the token calculation is successful.
     */
    struct ZegoToken04Result {
        std::string token;
        ErrorInfo   errorInfo;
    };
}  // namespace SERVER_ASSISTANT
}  // namespace ZEGO

#endif  //__ZegoServerAssistantDefines__