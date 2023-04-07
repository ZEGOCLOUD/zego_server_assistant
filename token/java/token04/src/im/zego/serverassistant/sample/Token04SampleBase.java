package im.zego.serverassistant.sample;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import im.zego.serverassistant.utils.TokenServerAssistant;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

//
// Base authentication token generation example
//

public class Token04Sample {
    public static void main(String[] args) {
        long appId = 1222222222L;    // Please replace with your appId, obtained from the Zego console
        String serverSecret = "12345678900987654321123456789012";  // Please replace with your serverSecret, obtained from the Zego console
        String userId = "test_user";    // Please replace with the user's userID, unique across the entire network under the same appId
        int effectiveTimeInSeconds = 300;   // Valid time, in seconds
        // Base authentication token, the payload field can be left empty
        String payload = "{\"payload\":\"payload\"}";  // Fill in the custom payload value, such as the example payload field. Not required, if not passed, it will be assigned null.
        TokenServerAssistant.VERBOSE = false;    // When debugging, set it to true, more information can be output to the console; when running formally, it is better to set it to false
        TokenServerAssistant.TokenInfo token = TokenServerAssistant.generateToken04(appId,  userId, serverSecret, effectiveTimeInSeconds, payload);
        System.out.println(token);

        if (token.error == null || token.error.code == TokenServerAssistant.ErrorCode.SUCCESS) {
            System.out.println("\r\ndecrypt the token ...");
            decryptToken(token.data, serverSecret);
        }
    }

    static private void decryptToken(String token, String secretKey) {
        String noVersionToken = token.substring(2);

        byte[] tokenBytes = Base64.getDecoder().decode(noVersionToken.getBytes());
        ByteBuffer buffer = ByteBuffer.wrap(tokenBytes);
        buffer.order(ByteOrder.BIG_ENDIAN);
        long expiredTime = buffer.getLong();
        System.out.println("expiredTime: " + expiredTime);
        int IVLength = buffer.getShort();
        byte[] ivBytes = new byte[IVLength];
        buffer.get(ivBytes);
        int contentLength = buffer.getShort();
        byte[] contentBytes = new byte[contentLength];
        buffer.get(contentBytes);

        try {
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);

            byte[] rawBytes = cipher.doFinal(contentBytes);
            JSONParser parser = new JSONParser();
            JSONObject json = (JSONObject)parser.parse(new String(rawBytes));
            System.out.println(json);
        } catch (Exception e) {
            System.out.println("decrypt failed: " + e);
        }
    }

}
