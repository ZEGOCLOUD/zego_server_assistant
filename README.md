# zego_server_assistant
ZEGOCLOUD Assistant SDK, ZEGOCLOUD-related product auxiliary tool code

# Introduction
This code repository is the ZEGOCLOUD service token generation tool library.

# Instructions

* For generating Token on the App terminal (not recommended), the terminal generates Token C++ and Java, and the server code is universal. Simply copy the file to your project and call the GenerateToken04 interface. For more details, please refer to sample.mm, and for higher-level access control, please refer to sample-for-rtcroom.mm.

     * OC: Copy \oc\rapidjson \oc\token04 to your project, and call the GenerateToken04 interface. For more details, please refer to sample.mm, and for higher-level access control, please refer to sample-for-rtcroom.mm.

     * C++: Copy the source files in \token\c++\token04 and the header files to your project, and call the GenerateToken04 interface. For more details, please refer to main.cc.

     * Java: Copy the source files in \java\token04\src to your project, and call the generateToken04 interface. For more details, please refer to Token04Sample.java. For higher-level access control, please refer to Token04ForRtcRoomSample.java.

* Note:
    * 1. The Token generation library uses the rapidjson library, and users can replace it with their own JSON library.
    * 2. The payload is a new parameter for version 04 Token (default is empty, or not passed), which is a JSON string used for higher-level access control. If you need this function, please contact ZEGOCLOUD technical support.
    * 3. Payload JSON format is as follows:
    ```json
    {  
		"room_id": "roomid", // Room ID, restricts users to log in to specific rooms. If it is empty, there is no restriction.   
		"privilege": {  
			"1": 1,   // Whether to allow login to the room. 1 for allow and 0 for close.      
			"2": 1   // Whether to allow streaming. 1 for allow and 0 for close.     
		},    
    	"stream_id_list": ["s123"] // Stream ID array. Restricts users to push specified streams. If stream_id_list is empty, there is no restriction.    
    }  
    ```