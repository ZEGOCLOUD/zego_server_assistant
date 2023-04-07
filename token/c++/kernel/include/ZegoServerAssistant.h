#ifndef __ZegoServerAssistant__
#define __ZegoServerAssistant__

#include <stdint.h>
#include <map>
#include <string>

#include "ZegoServerAssistantDefines.h"

namespace ZEGO
{
namespace SERVER_ASSISTANT
{
    class ZEGOSA_API ZegoServerAssistant
    {
    public:
        /**
         *  Static method to get token
         *
         *  appID: The unique identifier for each developer that Zego assigns
         *  userID: User ID
         *  secret: The key required for AES encryption during token authentication token calculation. A 32-byte string.
         *  effectiveTimeInSeconds: The validity period of the token, in seconds.
         *  payload: Additional information that can be carried by the token.
         *  ZegoTokenResult
         */
        static ZegoToken04Result GenerateToken04(uint32_t appID, const std::string& userID, const std::string& secret, int64_t effectiveTimeInSeconds, const std::string& payload);
    };
}  // namespace SERVER_ASSISTANT

}  // namespace ZEGO

#endif  // __ZegoServerAssistant__