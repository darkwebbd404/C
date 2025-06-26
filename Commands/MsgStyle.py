import threading
import jwt
import random
from threading import Thread
import json
import requests
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import json
import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
from byte import*
####################################
paylod_token1 = "1a13323032352d30322d32362031343a30333a3237220966726565206669726528013a07312e3130392e334239416e64726f6964204f532039202f204150492d32382028504b51312e3138303930342e3030312f5631312e302e332e302e5045494d49584d294a0848616e6468656c64520d4d61726f632054656c65636f6d5a1243617272696572446174614e6574776f726b60dc0b68ee0572033333327a1d41524d3634204650204153494d4420414553207c2031383034207c203880019d1d8a010f416472656e6f2028544d29203530399201404f70656e474c20455320332e322056403333312e30202847495440636635376339632c204931636235633464316363292028446174653a30392f32332f3138299a012b476f6f676c657c34303663613862352d343633302d343062622d623535662d373834646264653262656365a2010d3130322e35322e3137362e3837aa0102656eb201206431616539613230633836633463303433666434616134373931313438616135ba010134c2010848616e6468656c64ca01135869616f6d69205265646d69204e6f74652035ea014030363538396138383431623331323064363962333138373737653939366236313838336631653162323463383263616365303439326231653761313631656133f00101ca020d4d61726f632054656c65636f6dd202023447ca03203734323862323533646566633136343031386336303461316562626665626466e003bd9203e803d772f003a017f803468004e7738804bd92039004e7739804bd9203c80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f6c69622f61726d3634e00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f626173652e61706bf00403f804028a050236349a050a32303139313138303734a80503b205094f70656e474c455332b805ff7fc00504ca05094750174f05550b5135d20506416761646972da05023039e0059239ea0507616e64726f6964f2055c4b717348543376464d434e5a7a4f4966476c5a52584e657a3765646b576b5354546d6a446b6a3857313556676d44526c3257567a477a324f77342f42726259412f5a5a304e302b59416f4651477a5950744e6f51384835335534513df805fbe4068806019006019a060134a2060134"
paylod_token2 = '1a13323032352d30322d32362031343a30333a3237220966726565206669726528013a07312e3130392e334239416e64726f6964204f532039202f204150492d32382028504b51312e3138303930342e3030312f5631312e302e332e302e5045494d49584d294a0848616e6468656c64520d4d61726f632054656c65636f6d5a1243617272696572446174614e6574776f726b60dc0b68ee0572033333327a1d41524d3634204650204153494d4420414553207c2031383034207c203880019d1d8a010f416472656e6f2028544d29203530399201404f70656e474c20455320332e322056403333312e30202847495440636635376339632c204931636235633464316363292028446174653a30392f32332f3138299a012b476f6f676c657c34303663613862352d343633302d343062622d623535662d373834646264653262656365a2010d3130322e35322e3137362e3837aa0102656eb201206431616539613230633836633463303433666434616134373931313438616135ba010134c2010848616e6468656c64ca01135869616f6d69205265646d69204e6f74652035ea014030363538396138383431623331323064363962333138373737653939366236313838336631653162323463383263616365303439326231653761313631656133f00101ca020d4d61726f632054656c65636f6dd202023447ca03203734323862323533646566633136343031386336303461316562626665626466e003bd9203e803d772f003a017f803468004e7738804bd92039004e7739804bd9203c80401d2043f2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f6c69622f61726d3634e00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d51614b46585768325f61717257642d434d58554d33673d3d2f626173652e61706bf00403f804028a050236349a050a32303139313138303734a80503b205094f70656e474c455332b805ff7fc00504ca05094750174f05550b5135d20506416761646972da05023039e0059239ea0507616e64726f6964f2055c4b717348543376464d434e5a7a4f4966476c5a52584e657a3765646b576b5354546d6a446b6a3857313556676d44526c3257567a477a324f77342f42726259412f5a5a304e302b59416f4651477a5950744e6f51384835335534513df805fbe4068806019006019a060134a2060134'
freefire_version = "ob48"
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
#GET TIMESTAMP
def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
#ENCODE PACKET
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
def get_random_color():
	color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[0000FF][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color
#Fix Number For Working
def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)
    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
#VARINT ENCRYPT
def Encrypt(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()
#GET RANDOM AVATAR
def get_random_avatar():
	avatar_list = ['902000061','902000060','902000064','902000065','902000066','902000066','902000074','902000075','902000077','902000078','902000084','902000085','902000087','902000091','902000094','902000306']
	random_avatar = random.choice(avatar_list)
	return  random_avatar
#PARSE RESULTS
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict
#DECODE TO HEX
def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result
#ENCODE MESSAGE
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')
#ENCODE API
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
#EXTRACT JWT FROM HEX
def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
#RESTART SCRIPT
def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass          
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)
#CLASS CLIENT          
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")
####################################
    #MAKE PACKET MESSAGE
    def GenResponsMsg(self, Msg, Enc_Id):
        key, iv = self.key, self.iv
        fields = {
 1: 1,
 2: {
  1: 3557944186,
  2: Enc_Id,
  3: 2,
  4: Msg,
  5: int(datetime.now().timestamp()),
  9: {
   
   2: int(get_random_avatar()),
   3: 901041021,
   4: 330,
   
   10: 1,
   11: 155
  },
  10: "en",
  13: {
   1: "https://graph.facebook.com/v9.0/104076471965380/picture?width=160&height=160",
   2: 1,
   3: 1
  }
 },
 14: ""
}
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    #SERVER!
    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        socket_client.connect((host,port))
        print(f" Con port {port} Host {host} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)                    
            if data2 == b"":                
                print("Connection closed by remote host")
                restart_program()
                break    
    #CLIENT
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        global socket_client
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))  
        thread = threading.Thread(
            target=self.sockf1, args=(tok, "98.98.162.78", 39698, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()    
        while True:
            data = clients.recv(9999)
            if "1200" in data.hex()[0:4] and b"/ms" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                try:
                    decoded_data = data.decode('utf-8')
                except UnicodeDecodeError:
                    decoded_data = data.decode('latin-1')
                if "/ms " in decoded_data:
                    message = decoded_data.split("/ms ")[1]
                    message = message.split("\n")[0]
                    cleaned_message = re.sub(r'[^\x20-\x7E]', '', message)
                    unwanted_chars = ["(J,"]
                    for char in unwanted_chars:
                        cleaned_message = cleaned_message.replace(char, "")
                    cleaned_message = " ".join(cleaned_message.split())
                    for i in range(1, len(cleaned_message) + 1):
                        partial_message = cleaned_message[:i]
                        clients.send(
                self.GenResponsMsg(                 f"""{get_random_color()}{partial_message}""", uid
                )
            )
                        time.sleep(0.2)
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN
    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        global paylod_token1
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex(paylod_token1)
        payload = payload.replace(b"2024-12-26 13:02:43", str(now).encode())
        payload = payload.replace(b"88332848f415ca9ca98312edcd5fe8bc6547bc6d0477010a7feaf97e3435aa7f", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"e1ccc10e70d823f950f9f4c337d7d20a", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        ip,port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return ip,port    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        global freefire_version
        url = "https://clientbp.common.ggbluefox.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': freefire_version,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }        
        max_retries = 3
        attempt = 0
        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                return ip, port            
            except requests.RequestException as e:
                pass
                attempt += 1
                time.sleep(2)
        pass
        return None, None
    def guest_token(self,uid , password):
        global client_secret
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": client_secret,"client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "06589a8841b3120d69b318777e996b61883f1e1b24c82cace0492b1e7a161ea3"
        OLD_OPEN_ID = "d1ae9a20c86c4c043fd4aa4791148aa5"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        global paylod_token2,freefire_version
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': freefire_version,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex(paylod_token2)
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            ip,port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            return(BASE64_TOKEN,key,iv,combined_timestamp,ip,port)
        else:
            return False
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds
    def seconds_to_hex(seconds):
        return format(seconds, '04x')    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s    
    def get_tok(self):
        global g_token
        token, key, iv, Timestamp, ip, port = self.guest_token(self.id, self.password)
        g_token = token
        print(ip, port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
        except Exception as e:
            print(f"Error processing token: {e}")
            return
        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'
            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
        except Exception as e:
            print(f"Error constructing final token: {e}")
        token = final_token
        self.connect(token, ip, port, 'anything', key, iv)
        return token, key, iv       
with open('accs.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    print(f"ID: {id}, Password: {password}")
    client = FF_CLIENT(id, password)
    client.start()    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []
for i in range(num_threads):
    ids_for_thread = ids_passwords[i % num_clients]
    id, password = ids_for_thread
    thread = threading.Thread(target=run_client, args=(id, password))
    threads.append(thread)
    time.sleep(0.1)
    thread.start()
for thread in threads:
    thread.join()
#RUN BOT   
if __name__ == "__main__":
    try:
        client_thread = FF_CLIENT(id="3764548065", password="D1EBDA566F7F888D5662E8A4F30D318C4760492D605F9663A7A49DDA6AA84800")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()