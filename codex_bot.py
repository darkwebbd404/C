import threading;import jwt;import random;import json;import requests;import google.protobuf;import datetime;from datetime import datetime;import base64;import logging;import re;import socket;import os;import binascii;import sys;import psutil;import time;from important_zitado import*;from time import sleep;from google.protobuf.timestamp_pb2 import Timestamp;from google.protobuf.json_format import MessageToJson;from protobuf_decoder.protobuf_decoder import Parser;from threading import Thread;from Crypto.Cipher import AES;from Crypto.Util.Padding import pad, unpad; import httpx;import urllib3; import MajorLoginRes_pb2;import psutil;import jwt_generator_pb2;import MajorLoginRes_pb2;import psutil
####################################
#FUCK SSL BY FOX
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
paylod_token1 = "1a13323032352d30322d32362031373a32343a3238220966726565206669726528013a07312e3130392e324232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c645210566572697a6f6e20576972656c6573735a045749464960800a68c00772033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001bf2e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e309a012b476f6f676c657c30666330653434362d636132372d346661612d383234612d643430643737373637646539a2010d32302e3137312e37332e323032aa0102766eb201206f70656e6964ba010134c2010848616e6468656c64ca010c676f6f676c65204730313141ea0140616363657373f00101ca0210566572697a6f6e20576972656c657373d2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003c68102e803d3e801f003af13f80392078004c8f3018804c681029004c8f3019804c68102b00404c80402d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d673865444530543236384674466d6e465a3255706d413d3d2f6c69622f61726de00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d673865444530543236384674466d6e465a3255706d413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313138313035b205094f70656e474c455332b805ff01c00504ca05224a034644040d5f5548030b165f03445e4a3e0f5754005c3d0a515f3b000d3b5a0561d2050750686f656e6978da0502415ae005e64fea05093372645f7061727479f2055c4b717348543767744b576b4b3067592f48776d647758496853697a3466516c645833596a5a654b383658425474684b41663162573456737a364469305338767172304a6334485833544d51384b6155553347655676597a574639493df805e7e4068806019006019a060134a2060134"
freefire_version = "ob48"
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
chat_ip = "98.98.162.82"
chat_port = 39698
key2 = "projects_xxx_3ei93k_codex_xdfox"
####################################
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader
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


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
####################################
#GET INFO BY PLAYER ID
def get_player_info(player_id):
    url = f"https://projects-fox-apis.vercel.app/player_info?uid={player_id}&key={key}"
    response = requests.get(url)    
    if response.status_code == 200:
        try:
            r = response.json()
            return {
                "Account Booyah Pass": f"{r.get('booyah_pass_level', 'N/A')}",
                "Account Create": f"{r.get('account_creation_date', 'N/A')}",
                "Account Level": f"{r.get('level', 'N/A')}",
                "Account Likes": f" {r.get('likes', 'N/A')}",
                "Name": f"{r.get('player_name', 'N/A')}",
                "UID": f" {r.get('player_id', 'N/A')}",
                "Account Region": f"{r.get('server', 'N/A')}",
                }
        except ValueError as e:
            pass
            return {
                "error": "Invalid JSON response"
            }
    else:
        pass
        return {
            "error": f"Failed to fetch data: {response.status_code}"
        }
#CHAT WITH AI
def talk_with_ai(question):
    url = f"https://princeaiapi.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    res = requests.get(url)
    if res.status_code == 200:
        data = res.json()
        msg = data["message"]["content"]
        return msg
    else:
        return "حدث خطأ أثناء الاتصال بالخادم."
#SPAM REQUESTS
def spam_requests(player_id):
    url = f"https://spam-fr-lk-team.vercel.app/send_requests?uid={player_id}"
    res = requests.get(url)
    if res.status_code == 200:
        return "Spam is Good"
    else:
        return "fuck spam"
import requests
####################################
import requests
def newinfo(uid):
    try:
        response = requests.get(f"https://projects-foxx-garena-apis.vercel.app/accinfo?uid={uid}&region=ME&api_key=CdxGfoxProjext1kmembers")
        
        if response.status_code == 200:
            response = response.json()
            basic_info = response['basicInfo']
            formatted_basic = {
                'level': basic_info.get('level', 0),
                'likes': basic_info.get('liked', 0),
                'username': basic_info.get('nickname', 'Unknown'),
                'region': basic_info.get('region', 'Unknown'),
                'bio': response.get('socialInfo', {}).get('socialHighlight', 'No Bio'),
                'brrankscore': basic_info.get('rankingPoints', 0),
                'Exp': basic_info.get('exp', 0)
            }
            
            # معالجة معلومات العشيرة (غير متوفرة في API الجديد بنفس الهيكل)
            clan_info = response.get('clanBasicInfo', {})
            if not clan_info:
                clan_info = "false"
                clan_admin_info = "false"
            else:
                # إذا كانت هناك معلومات عشيرة ولكن بهيكل مختلف
                clan_admin_info = {
                    'adminname': 'Unknown',
                    'brpoint': 0,
                    'exp': 0,
                    'idadmin': 0,
                    'level': 0
                }
                # يمكنك تعديل هذا الجزء حسب البيانات المتاحة فعلياً
                clan_info = {
                    'clanid': clan_info.get('id', 0),
                    'clanname': clan_info.get('name', 'Unknown Clan'),
                    'guildlevel': clan_info.get('level', 0),
                    'livemember': clan_info.get('membersCount', 0)
                }
            
            info = {
                'basic_info': formatted_basic,
                'clan_info': clan_info,  # ملاحظة: هناك خطأ إملائي هنا (clan_info بدلاً من clan_info)
                'clan_admin': clan_admin_info
            }
            return {"status": "ok", "info": info}
        else:
            return {"status": "wrong_id"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
	
#ADDING-100-LIKES-IN-24H
import requests

def send_likes(uid):
    try:
        likes_api_response = requests.get(
            f"https://mazidgamerlike-amber.vercel.app/like?uid={uid}&server_name=me&key=taitan_gay_leaker"
        )
        
        message = (
            f"[C][B][FF0000]________________________\n"
            f" Wrong ID .......\n"
            f" Please Check Again\n"
            f"________________________"
        )
        
        if likes_api_response.status_code == 200:
            api_json_response = likes_api_response.json()
            
            # التحقق من حالة الإعجابات (status 2 يعني أن العملية لم تنجح)
            if api_json_response.get('status') != 2:
                player_name = api_json_response.get('PlayerNickname', 'Unknown')
                likes_before = api_json_response.get('LikesbeforeCommand', 0)
                likes_after = api_json_response.get('LikesafterCommand', 0)
                likes_added = api_json_response.get('LikesGivenByAPI', 0)
                
                message = (
                    f"________________________\n"
                    f" Likes Status :\n"
                    f" LIKES SENT !\n\n"
                    f" PLAYER NAME : {player_name}\n"
                    f" LIKES ADDED : {likes_added}\n"
                    f" LIKES BEFORE : {likes_before}\n"
                    f" LIKES AFTER : {likes_after}\n"
                    f"________________________"
                )
            else:
                message = (
                    f"[C][B][FF0000]________________________\n"
                    f" لقد وصلت الى الحد اليومي في لايكات حاول بعد 24 ساعة\n"
                    f" (Status: {api_json_response.get('status')})\n"
                    f"________________________"
                )
                
        return message
    except Exception as e:
        return f"Error: {str(e)}"
####################################
#CHECK ACCOUNT IS BANNED
def check_banned_status(player_id):
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
####################################
def Encrypt(number):
    try:
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
    except:
        restart_program()
#############CLASS RANDOM###########
def  generate_random_word():
    word_list = [
        "XNXXX", "ZBI", "CODEX TEAM", "NIKMOK",
        "PUSY", "FUCK YOU", "fuke_any_team", "انيك_امك", "PORNO",
        "FUCK YOUR MATHER", "نيك_ختك", "MOROOCOO", "kissss omkk", "امك_كسها_وردي",
        "WAAA DAK W9", "ZAMLLL", "يانقش", "9WAD", "طبونك_مقود",
        "كسك", "انيكمك", "اقعد_يعرص", "اححح", "DIMA RAJA",
        "ستريمرز_فاشل", "FOXXXX", "يخول", "ترمتك_غوز", "سوتك_جميله",
        "هههههههههههه", "سوتك_غوز", "يانيكمك", "ابلع_ياعرص", "يا_لبوت",
        "يازبي", "كسك_قوه", "كسك", "انطلق_فكسك", "يافاشل",
        "يازانيه", "ياقلوتي", "كسك", "نشدك_نحوؤك", "سوتك",
        "يافاشل", "نيكمك", "كوسمك", "يكسمك", "هضرب_عشره_عليك", "لحاااااس", " FOXXX", "TELEGRAM:@S_DD_F"
    ]

    return random.choice(word_list)
def generate_random_color():
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
    "[90EE90][b][c]",
    "[FF4500][b][c]",
    "[FFD700][b][c]",
    "[32CD32][b][c]",
    "[87CEEB][b][c]",
    "[9370DB][b][c]",
    "[FF69B4][b][c]",
    "[8A2BE2][b][c]",
    "[00BFFF][b][c]",
    "[1E90FF][b][c]",
    "[20B2AA][b][c]",
    "[00FA9A][b][c]",
    "[008000][b][c]",
    "[FFFF00][b][c]",
    "[FF8C00][b][c]",
    "[DC143C][b][c]",
    "[FF6347][b][c]",
    "[FFA07A][b][c]",
    "[FFDAB9][b][c]",
    "[CD853F][b][c]",
    "[D2691E][b][c]",
    "[BC8F8F][b][c]",
    "[F0E68C][b][c]",
    "[556B2F][b][c]",
    "[808000][b][c]",
    "[4682B4][b][c]",
    "[6A5ACD][b][c]",
    "[7B68EE][b][c]",
    "[8B4513][b][c]",
    "[C71585][b][c]",
    "[4B0082][b][c]",
    "[B22222][b][c]",
    "[228B22][b][c]",
    "[8B008B][b][c]",
    "[483D8B][b][c]",
    "[556B2F][b][c]",
    "[800000][b][c]",
    "[008080][b][c]",
    "[000080][b][c]",
    "[800080][b][c]",
    "[808080][b][c]",
    "[A9A9A9][b][c]",
    "[D3D3D3][b][c]",
    "[F0F0F0][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color
def get_random_avatar():
    avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066', 
        '902000074', '902000075', '902000077', '902000078', '902000084', 
        '902000085', '902000087', '902000091', '902000094', '902000306','902000091','902000208','902000209','902000210','902000211','902047016','902047016','902000347'
    ]
    return random.choice(avatar_list)
############CLASS: PANEL#############
#Get-jwt-token and Updatet in 8h
def get_jwt_token():
    global jwt_token
    url = "https://projects-fox-x-get-jwt.vercel.app/get?uid=3840462225&password=A1AD003C1B4761C96F1168410AD5EA557BE8E837E8A75B99BE9A34EEC4154492"
    try:
        response = httpx.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                jwt_token = data['token']
                print(jwt_token)
            else:
                pass
        else:
            pass
    except httpx.RequestError as e:
        print(f"Request error: {e}")
def token_updater():
    while True:
        get_jwt_token()
        time.sleep(8 * 3600)
token_thread = Thread(target=token_updater, daemon=True)
token_thread.start()
def get_time(uid):
    url = f"http://168.231.113.96:4001/get_time/{uid}"
    res = requests.get(url)
    data = res.json()
    if "error" in data:
        return "time:Expired - Player has been removed"
        remove_result = remove_player(uid)
    else:
        data = res.json()['remaining_time']
        days = data['days']
        hours = data['hours']
        minutes = data['minutes']
        seconds = data['seconds']
        time = f"""[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
-Days: {days}
-Hours: {hours}
-Minutes: {minutes}
-Seconds: {seconds}
  
•U Need Free More Time? Dm Telegram: @S_DD_F
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]Credits: ProjectS FoxX!!"""
        return time

def remove_player(player_id):
    url = f"https://projects-fox-apis.vercel.app/remove_friend?token={jwt_token}&id={player_id}&key={key2}"
    res = requests.get(url)
    if res.status_code == 200:
        print('Done')
        data = res.json()
        return data
    else:
        print("Error removing player")
        return None
####################################
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break           
#GET AVAILABLE ROOM
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
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
####################################
def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
####################################
def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = psutil.net_connections()
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
          
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def  nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in  self.nmnmmmmn: {e}")

    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: f"{generate_random_color()}{generate_random_word()}",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "ME",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 11497463104
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)    
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)   
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            10: int(get_random_avatar()),
            2: "ME",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)   
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)   
        return bytes.fromhex(final_packet)
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "ME",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)   
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)    
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)        
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)        
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 11497463104,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)    
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)   
        return bytes.fromhex(final_packet)
   
    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 11497463104
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)    
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)    
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 11497463104
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
            1: 1,
            2: {
            1: 657852060,
            2: Enc_Id,
            3: 2,
            4: str(Msg),
            5: int(datetime.now().timestamp()),
            9: {
            1:  "Ｃ４ㅤＴＥＡＭ",
            2: int(get_random_avatar()),
            4: 330,
            8: "Ｃ４ㅤＴＥＡＭ",
            10: 1,
            11: 1
            },
            10: "en",
            13: {
            3: 1
            },
            14: ""
        }
    }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        prefix = "121500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)        
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "wW_T",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)        
        prefix = "051500" + "0" * (6 - len(header_lenth_final))
        final_packet = prefix + header_lenth_final +  self.nmnmmmmn(packet)   
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
     #SPAM ROOM VIA UID
    def packetspam(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: f"{generate_random_color()}{generate_random_word()}",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final +  self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final +  self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)

        socket_client.connect((host,port))
        print(f" Con port {port} Host {host} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)
            print(data2)
            if "0500" in data2.hex()[0:4] and len(data2.hex()) > 30:
                if sent_inv == True:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    print(accept_packet)
                    print(tempid)
                    aa = gethashteam(accept_packet)
                    ownerid = getownteam(accept_packet)
                    print(ownerid)
                    print(aa)
                    ss = self.accept_sq(aa, tempid, int(ownerid))
                    socket_client.send(ss)
                    sleep(1)
                    startauto = self.start_autooo()
                    socket_client.send(startauto)
                    start_par = False
                    sent_inv = False
            if data2 == b"":                
                print("Connection closed by remote host")

            if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    print(parsed_data)
                    idinv = parsed_data["5"]["data"]["1"]["data"]
                    nameinv = parsed_data["5"]["data"]["3"]["data"]
                    senthi = True
            if "0f00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                
                asdj = parsed_data["2"]["data"]
                tempdata = get_player_status(packett)
                if asdj == 15:
                    if tempdata == "-OFFLINE":
                        tempdata = f"-THE ID IS {tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            
                            tempdata = f"-ID : {idplayer1}\nstatus : {tempdata}\n-ID ROOM : {idrooom1}"
                            data22 = packett
                            print(data22)
                            
                        if "INSQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"-ID : {idplayer1}\n-STATUS : {tempdata}\n-LEADEER ID : {idleader1}"
                        else:
                            tempdata = f"-ID : {idplayer1}\n-STATUS : {tempdata}"
                    statusinfo = True 

                    print(data2.hex())
                    print(tempdata)
                
                    

                else:
                    pass
            if "0e00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                idplayer1 = fix_num(idplayer)
                asdj = parsed_data["2"]["data"]
                tempdata1 = get_player_status(packett)
                if asdj == 14:
                    nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                    
                    maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                    maxplayer1 = fix_num(maxplayer)
                    nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                    nowplayer1 = fix_num(nowplayer)
                    tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"       
            if data2 == b"":
                
                print("Connection closed by remote host")
                restart_program()
                break
    import re
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global leaveee
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global pleaseaccept
        global tempdata1
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, chat_ip, chat_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()

        while True:
            data = clients.recv(9999)

            if data == b"":
                print("Connection closed by remote host")
                break
                print(f"Received data: {data}")
            
            if senthi == True:
                
                clients.send(
                        self.GenResponsMsg(
                            f"""[C][B]السلام عليكم كيف حالك شكرا على قبول طلب صداقة ارسل ايموجي لمعرفة ما عليك فعله""", idinv
                        )
                )
                senthi = False            
            if "1200" in data.hex()[0:4]:
               
                json_result = get_available_room(data.hex()[10:])
                print(data.hex())
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                    uexmojiii = parsed_data["5"]["data"]["8"]["data"]
                    if uexmojiii == "DefaultMessageWithKey":
                        pass
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"""[C][B]
────୨ৎ────
「 ✦ 𓆩 F O X  B O T V2 𓆪 ✦ 」

مرحبًا بك في بوت فوكس - النسخة الثانية  
البوت المجاني الوحيد بدون أي دفوعات!

يتم تطوير الميزات باستمرار  
فاستمتع بوقتك أثناء الاستخدام.

إذا واجهت أي مشكلة، تواصل مع المطوّر:

[00ff00]@S_DD_F
[ffffff][C][B]
لعرض قائمة الأوامر:
[00ff00]    
/🗿help
[ffffff][C][B]
────୨ৎ────
""",uid
                            )
                        )
                else:
                    pass
####################################
            #SEND SKWAD 5 TO ID ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/snd/" in data:
                try:
                    message = data.decode('utf-8', errors='ignore')
                    unwanted_chars = ["(J,", "(J@", "(", ")", "@", ","]
                    cleaned_message = message
                    for char in unwanted_chars:
                        cleaned_message = cleaned_message.replace(char, "")
                    
                    try:
                        message_parts = cleaned_message.split()
                        iddd = None
                        for part in message_parts:
                            if '/snd/' in part:
                                digits = ''.join(filter(str.isdigit, part.split('/snd/')[1]))
                                if digits:
                                    iddd = int(digits)
                                    break
                        if iddd is None:
                            iddd = 10414593349
                    except:
                        iddd = 10414593349
                    
                    packetfinal = self.changes(4)
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)
                    sleep(1)
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    iddd = fix_num(iddd)
                    clients.send(self.GenResponsMsg(f"""
            [11EAFD][b][c]
            ────୨ৎ────
            تم فتح سكواد 5 الى الاعب : 
            {iddd}
            ────୨ৎ────
            [C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
            """,uid))
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
                except Exception as e:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        clients.send(self.GenResponsMsg("[FF0000][b]❗ حدث خطأ في العملية[/b]",uid))
                    except:
                        restart_program()
####################################
            #MAKE SKWAD 3 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/3s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)             
                sleep(1)
                packetfinal = self.changes(2)
                iddd=parsed_data["5"]["data"]["1"]["data"]
                print("\n\n")
                print(iddd)
                print("\n\n")
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if iddd:
	                clients.send(
	                    self.GenResponsMsg(
	                        f"""
[11EAFD][b][c]
────୨ৎ────
إقبل طلب بسرعة!!!

────୨ৎ────
[C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
	                        """, iddd
	                    )
	                )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee)   
            #MAKE SKWAD 4 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/4s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)             
                sleep(1)
                packetfinal = self.changes(3)
                iddd=parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if iddd:
	                clients.send(
	                    self.GenResponsMsg(
	                        f"""
[11EAFD][b][c]
────୨ৎ────
إقبل طلب بسرعة!!!

────୨ৎ────
[C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
	                        """, iddd
	                    )
	                )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee) 
            #MAKE SKWAD 5 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/5s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)             
                sleep(1)
                packetfinal = self.changes(4)
                iddd=parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if iddd:
	                clients.send(
	                    self.GenResponsMsg(
	                        f"""
[11EAFD][b][c]
────୨ৎ────
إقبل طلب بسرعة!!!

────୨ৎ────
[C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
	                        """, iddd
	                    )
	                )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee) 
####################################
            # GET PLAYER COMMAND
            if "1200" in data.hex()[0:4] and b"/inv/" in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    iddd = default_id
                    
                    try:
                        import re
                        # البحث عن نمط /inv/ متبوعًا بأرقام
                        id_match = re.search(r'/inv/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            iddd = id_match.group(1)
                             
                            if not (5 <= len(iddd) <= 15) or not iddd.isdigit():
                                iddd = default_id
                        else:
                             
                            temp_id = cleaned_message.split('/inv/')[1].split()[0].strip()
                            iddd = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                        
                        # معالجة الرموز الخاصة
                        iddd = iddd.replace("***", "106") if "***" in iddd else iddd
                        
                    except Exception as e:
                        print(f"Player ID extraction error: {e}")
                        iddd = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    numsc = 5
                    
                    # إرسال الحزم
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)
                    sleep(1)
                    packetfinal = self.changes(numsc)
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    invitessa = self.invite_skwad(uid)
                    socket_client.send(invitessa)
                    
                    clients.send(self.GenResponsMsg(f"""
            [11EAFD][b][c]
            ────୨ৎ────
            إقبل طلب بسرعة!!!
            ────୨ৎ────
            [C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
            """, uid))
                    
                    sleep(9)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
            
                except Exception as e:
                    print(f"Get Player Command Error: {e}")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]خطأ: {e}" if "ID" in str(e) else f"[FF0000]خطأ في جلب اللاعب: {e}"
                        clients.send(self.GenResponsMsg(error_msg, uid))
                    except:
                        restart_program()

            # SPAM JOIN SKWAD COMMAND
            if "1200" in data.hex()[0:4] and b"/sm/" in data:
                try:
                    
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                   
                    default_id = 10414593349
                    iddd = default_id
                    
                    try:
                        import re
                        
                        id_match = re.search(r'/sm/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            iddd = int(id_match.group(1))
                            
                            if not (5 <= len(str(iddd)) <= 15):
                                iddd = default_id
                        else:
                            
                            temp_id = cleaned_message.split('/sm/')[1].split()[0].strip()
                            iddd = int(temp_id) if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as e:
                        print(f"Spam ID extraction error: {e}")
                        iddd = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    invskwad = self.request_skwad(iddd)
                    socket_client.send(invskwad)
                    parsed_data = json.loads(json_result)
                    
                   
                    for _ in range(30):
                        socket_client.send(invskwad)
                    
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    iddd_display = fix_num(iddd)
                    clients.send(self.GenResponsMsg(f"""
            [11EAFD][b][c]
            ────୨ৎ────
            تم بدأ السبام طلبات إنضمام للاعب:
            {iddd_display}
            ────୨ৎ────
            [C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
            """, uid))
                    
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
            
                except Exception as e:
                    print(f"Spam Command Error: {e}")
                    restart_program()
            # PLAYER STATUS COMMAND
            if "1200" in data.hex()[0:4] and b"/status/" in data:
                try:
                    
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    player_id = default_id
                    
                    try:
                        
                        import re
                        id_match = re.search(r'/status/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            player_id = id_match.group(1)
                            
                            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                                player_id = default_id
                        else:
                            
                            temp_id = cleaned_message.split('/status/')[1].split()[0].strip()
                           
                            temp_id = temp_id.replace("***", "106") if "***" in temp_id else temp_id
                            player_id = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as extract_error:
                        print(f"ID extraction error: {extract_error}")
                        player_id = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    
                    
                    packetmaker = self.createpacketinfo(player_id)
                    socket_client.send(packetmaker)
                    sleep(1)
                    
                    
                    if statusinfo:
                        status_msg = f"[b][C][00FFFF]{tempdata}"
                        clients.send(self.GenResponsMsg(status_msg, uid))
                        
                except Exception as e:
                    print(f"Player Status Command Error: {e}")
                    try:
                        
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error processing status request"
                        clients.send(self.GenResponsMsg(error_msg, uid))
                    except:
                        restart_program()

####################################
            #CHECK ID ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/check/" in data:
                try:
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    print(f"\nRaw Message: {raw_message}\nCleaned Message: {cleaned_message}\n")
                    import re
                    id_match = re.search(r'/check/(\d{5,15})\b', cleaned_message)                    
                    if not id_match:
                        id_match = re.search(r'/check/([0-9]+)', cleaned_message)                    
                    if id_match:
                        player_id = id_match.group(1)
                        print(f"Extracted Player ID: {player_id}")
                        if not (5 <= len(player_id) <= 15):
                            raise ValueError("Invalid ID length (5-15 digits required)")
                    else:
                        raise ValueError("No valid player ID found in message")
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg("Okay Sir, Please Wait..", uid))
                    banned_status = check_banned_status(player_id)
                    player_id = fix_num(player_id)
                    status = banned_status['status']
                    response_message = f"""
            [11EAFD][b][c]
            ────୨ৎ────
            Player Name: {banned_status['player_name']}
            Player ID : {player_id}
            Status: {status}
            ────୨ৎ────
            [C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
            """
                    clients.send(self.GenResponsMsg(response_message, uid))
                except Exception as e:
                    print(f"\nProcessing Error: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: Failed to process command - {e}"
                        clients.send(self.GenResponsMsg(error_msg, uid))
                    except Exception as inner_e:
                        print(f"\nCritical Error: {inner_e}\n")
                        restart_program()
####################################
            #GET ID REGION ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/region/" in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    print(f"\nRaw Message: {raw_message}\nCleaned Message: {cleaned_message}\n")
            
                    # استخراج ID باستخدام regex
                    import re
                    id_match = re.search(r'/region/(\d{5,15})\b', cleaned_message)
                    
                    if not id_match:
                        # محاولة بديلة إذا فشلت الأولى
                        id_match = re.search(r'/region/(\d+)', cleaned_message)
                    
                    if id_match:
                        player_id = id_match.group(1)
                        print(f"Extracted Player ID: {player_id}")
                        
                        # التحقق من طول ID
                        if not (5 <= len(player_id) <= 15):
                            raise ValueError("يجب أن يكون طول الآيدي بين 5-15 رقم")
                    else:
                        raise ValueError("لم يتم العثور على آيدي لاعب صالح في الرسالة")
            
                    # المتابعة مع باقي العمليات
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg("جاري المعالجة...", uid))
                    
                    b = get_player_info(player_id)
                    player_id = fix_num(player_id)
                    response_message = f"""
            [11EAFD][b][c]
            ────୨ৎ────
            Player Name : {b.get('Name', 'N/A')}
            Player ID : {player_id}
            Player Region : {b.get('Account Region', 'N/A')}
            ────୨ৎ────
            [C][b]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
            """
                    clients.send(self.GenResponsMsg(response_message, uid))
            
                except Exception as e:
                    print(f"\nError: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]خطأ: {e}" if "آيدي" in str(e) else f"[FF0000]خطأ في المعالجة: {e}"
                        clients.send(self.GenResponsMsg(error_msg, uid))
                    except Exception as inner_e:
                        print(f"\nCritical Error: {inner_e}\n")
                        restart_program()
            #
            if "1200" in data.hex()[0:4] and b"/spm/" in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    default_id = "10414593349"
                    player_id = default_id  # القيمة الافتراضية
                    
                    try:
                        import re
                        # المحاولة الأولى: البحث عن نمط /spm/ متبوعًا بأرقام
                        id_match = re.search(r'/spm/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            player_id = id_match.group(1)
                            print(f"Extracted Player ID: {player_id}")
                            
                            # التحقق من صحة الآيدي
                            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                                print("Invalid ID format, using default")
                                player_id = default_id
                        else:
                            # المحاولة الثانية: طريقة بديلة إذا فشلت الأولى
                            parts = cleaned_message.split('/spm/')
                            if len(parts) > 1:
                                temp_id = parts[1].split()[0].strip()
                                if temp_id.isdigit() and 5 <= len(temp_id) <= 15:
                                    player_id = temp_id
                                else:
                                    print("Invalid ID in fallback method, using default")
                                    player_id = default_id
                            else:
                                print("No ID found, using default")
                                player_id = default_id
                                
                    except Exception as extract_error:
                        print(f"ID extraction error: {extract_error}, using default")
                        player_id = default_id
            
                    # المتابعة مع باقي العمليات
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg("جاري المعالجة...", uid))
                    
                    b = spam_requests(player_id)
                    player_id = fix_num(player_id)
                    response_message = f"""
            [11EAFD][b][c]
            ────୨ৎ────
            Status : {fix_num(b)}
            Player ID : {player_id}
            ────୨ৎ────
            [C][B]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
            """
                    clients.send(self.GenResponsMsg(response_message, uid))
            
                except Exception as e:
                    print(f"\nProcessing Error: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: {str(e)}"
                        clients.send(self.GenResponsMsg(error_msg, uid))
                    except:
                        restart_program()
            # AI COMMAND
            if "1200" in data.hex()[0:4] and b"/ai" in data:
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    
                    clients.send(self.GenResponsMsg("جاري تواصل معا شات جيبتي....", uid))
                    
                    # استخراج السؤال بطريقة أكثر قوة
                    try:
                        raw_message = data.decode('utf-8', errors='ignore').replace('\x00', '')
                        question_part = raw_message.split('/ai')[1]
                        
                        # تنظيف السؤال من الرموز غير المرغوبة
                        unwanted_chars = ["***", "\\x", "\x00"]
                        cleaned_question = question_part
                        for char in unwanted_chars:
                            cleaned_question = cleaned_question.replace(char, "")
                            
                        question = cleaned_question.strip()
                        if not question:
                            raise ValueError("No question provided")
                            
                        # استبدال *** بقيمة افتراضية
                        question = question.replace("***", "106") if "***" in question else question
                        
                        ai_msg = talk_with_ai(question)
                        clients.send(self.GenResponsMsg(ai_msg, uid))
                        
                    except Exception as ai_error:
                        print(f"AI Processing Error: {ai_error}")
                        restart_program()
            
                except Exception as e:
                    print(f"AI Command Error: {e}")
                    restart_program()


####################################
            if "1200" in data.hex()[0:4] and b"/room/" in data:
                	import re
                	i = re.split("/room/", str(data))[1] 
                	sid = str(i).split("(\\x")[0]
                	json_result = get_available_room(data.hex()[10:])
                	parsed_data = json.loads(json_result)
                	uid = parsed_data["5"]["data"]["1"]["data"]
                	split_data = re.split(rb'/room/', data)
                	room_data = split_data[1].split(b'(')[0].decode().strip().split()
                	if room_data and len(room_data) > 0:
                    		player_id = room_data[0]
                    
                    		if not any(char.isdigit() for char in player_id):
                    			clients.send(self.GenResponsMsg(f"[C][B][ff0000] - Error! ", uid))
                    		else:
                    			player_id = room_data[0]
                    		if player_id.isdigit():
                        		if "***" in player_id:
                            			player_id = rrrrrrrrrrrrrr(player_id)                        			
                        		packetmaker = self.createpacketinfo(player_id)
                        		socket_client.send(packetmaker)
                        		sleep(0.5)
                        		if "IN ROOM" in tempdata:
                            			room_id = get_idroom_by_idplayer(data22)
                            			packetspam = self.spam_room(room_id, player_id)
                            			print(packetspam.hex())
                            			clients.send(
                                self.GenResponsMsg(
                                    f"\n{generate_random_color()}- SpAm StArtEd For uid {fix_num(player_id)} !\n", uid
                                )
                            )
                            
                            
                            			for _ in range(10):
#                                sleep(0.5)
                                			packetspam = self.spam_room(room_id, player_id)

                                			print(" sending spam to "+player_id)
                                			threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                            			clients.send(
                                self.GenResponsMsg(
                                    f"\n\n\n{generate_random_color()} [00FF00]Successfully Spam SeNt !\n\n\n", uid
                                )
                            )
                        		else:
                        		      clients.send(
                                self.GenResponsMsg(
                                    f"\n\n\n[C][B] [FF00FF]The player is not in room\n\n\n", uid
                                )
                            )      
                    		else:
                    		      clients.send(
                            self.GenResponsMsg(
                                f"\n\n\n[C][B] [FF00FF]Please write the id of player not!\n\n\n", uid
                            )
                        )   
                	else:
                	       clients.send(
                        self.GenResponsMsg(
                            f"\n\n\n[C][B] [FF00FF]Please write the id of player !\n\n\n", uid
                        )
                    )                          
####################################
            if "1200" in data.hex()[0:4] and b"/info" in data:
	                import re
	                command_split = re.split("/info", str(data))
	                if len(command_split) > 1:
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    sender_id = parsed_data["5"]["data"]["1"]["data"]
	                    sender_name = parsed_data['5']['data']['9']['data']['1']['data']
	                    uid = command_split[1].split("\\x")[0].strip()
	                    uid = command_split[1].split('(')[0].strip()
	                    print(uid)
	                    info_response = newinfo(uid)
	                    print(uid)
	                    uid = uid + 'َKKKKKKKKKKKKK'
	                    infoo = info_response['info']
	                    print(infoo)
	                    basic_info = infoo['basic_info']
	                    clan_info = infoo['clan_info']
	                    clan_admin = infoo['clan_admin']
	                    print(clan_info)
	                    if clan_info == "false":
	                    	clan_info = "\nPlayer Not In Clan\n"
	                    else:
	                    	clan_id = clan_info['clanid']
	                    	clan_name = clan_info['clanname']
	                    	clan_level = clan_info['guildlevel']
	                    	clan_members = clan_info['livemember']
	                    	clan_admin_name = clan_admin['adminname']
	                    	clan_admin_brrank = clan_admin['brpoint']
	                    	clan_admin_exp = clan_admin['exp']
	                    	clan_admin_id = fix_num(clan_admin['idadmin'])
	                    	clan_admin_level = clan_admin['level']
	                    	clan_info = (	                        f" Clan Info :\n"
	                    	f"Clan ID : {fix_num(clan_id)}\n"
	                         f"Clan Name :  {clan_name}\n"
	                        f"Clan Level: {clan_level}\n\n"
	                        "Clan Admin Info:: \n"
	                        f"ID : {clan_admin_id}\n"
	                        f"Name : {clan_admin_name}\n"
	                        f"Exp : {clan_admin_exp}\n"
	                        f"Level : {clan_admin_level}\n"
	                        f"Ranked (Br) Score : {clan_admin_brrank}\n"
	                        )
	                    
	                    if info_response['status'] == "ok":
		                    level = basic_info['level']
		                    likes = basic_info['likes']
		                    name = basic_info['username']
		                    region = basic_info['region']
		                    bio = basic_info['bio']
		                    if "|" in bio:
		                    	bio = bio.replace("|"," ")
		                    br_rank = fix_num(basic_info['brrankscore'])
		                    exp = fix_num(basic_info['Exp'])
		                    print(level,likes,name,region)
		                    message_info = (	                    
	                        f"[C][FFB300] Basic Account info :\n"
	                        f"Server : {region}\n"
	                        f"Name : {name}\n"
	                        f"Bio : {bio}\n"
	                        f"Level : {level}\n"
	                        f"Exp : {exp}\n"
	                        
	                        f"Likes : {fix_num(likes)}\n"
	                        f"Ranked (Br) Score : {br_rank}"
	                        

   f"{clan_info}\n"
   f"[FF0000]Command Sent By : {sender_name}\n"
   f"Command Sender Id : {fix_num(sender_id)}\n\n"
   
	                        

	                        )
	                    else:
	                    	message_info = (f"[C][B] [FF0000]-----------------------------------\n"
	                        f" Wrong ID ..\n"
	                         f" Please Check Again\n"
	                        
	                        f"-----------------------------------")
	                    
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    clients.send(
	                    self.GenResponsMsg(
	                        f"{generate_random_color()}Okay Sir, Please Wait..", uid
	                    )
	                )
	                    json_result = get_available_room(data.hex()[10:])
	                    parsed_data = json.loads(json_result)
	                    uid = parsed_data["5"]["data"]["1"]["data"]
	                    print(message_info)
	                    clients.send(self.GenResponsMsg(message_info, uid))               	     
####################################
            # GET 100 LIKES COMMAND
            import re
            if "1200" in data.hex()[0:4] and b"/likes/" in data:
                import re
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    player_id = default_id
                    
                    try:
                        id_match = re.search(r'/likes/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            player_id = id_match.group(1)
                             
                            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                                player_id = default_id
                        else:                             
                            temp_id = cleaned_message.split('/likes/')[1].split()[0].strip()
                            player_id = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as e:
                        print(f"Likes ID extraction error: {e}")
                        player_id = default_id               
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    clients.send(self.GenResponsMsg("جاري إرسال الإعجابات...", uid))
                    
                    likes_info = send_likes(player_id)
                    player_id = fix_num(player_id)
                    clients.send(self.GenResponsMsg(likes_info, uid))
            
                except Exception as e:
                    print(f"Likes Command Error: {e}")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]خطأ: {e}" if "ID" in str(e) else f"[FF0000]خطأ في الإعجابات: {e}"
                        clients.send(self.GenResponsMsg(error_msg, uid))
                    except:
                        restart_program()

####################################
            if "1200" in data.hex()[0:4] and b"/help" in data:	                
	                lines = "_"*20	                
	                json_result = get_available_room(data.hex()[10:])
	                parsed_data = json.loads(json_result)
	                user_name = parsed_data['5']['data']['9']['data']['1']['data']
	                uid = parsed_data["5"]["data"]["1"]["data"]
	                player_time_left = get_time(uid)
	                clients.send(self.GenResponsMsg(player_time_left, uid))
	                response_message = f"""
[C][B]commands!
[ffffff]
فتح فريق لصديقك استعمل:
[00ff00]/🗿snd/104[c]145[c]933[c]49
[ffffff]
تحويل الفريق الى 3 استعمل:
[00ff00]/🗿3s
[ffffff]
تحويل الفريق الى 4 استعمل:
[00ff00]/🗿4s
[ffffff]
تحويل الفريق الى 5 استعمل:
[00ff00]/🗿5s
[ffffff]
جلب لاعب الى الفريق استعمل:
[00ff00]/🗿inv/104[c]145[c]933[c]49
[ffffff]
سبام طلبات انضمام للفريق استعمل:
[00ff00]/🗿sm/104[c]145[c]933[c]49
[ffffff]
سبام رومات استعمل:
[00ff00]/🗿room/104[c]145[c]933[c]49
[ffffff]
جلب معلومات لاعب استعمل:
[00ff00]/🗿info 104[c]145[c]933[c]49
[ffffff]
معرفة حالة لاعب استعمل:
[00ff00]/🗿status/104[c]145[c]933[c]49

[C][B][69FFB4]────୨ৎ────"""
	                clients.send(self.GenResponsMsg(response_message, uid))
	                response_mssg = f"""
[C][B][69FFB4]────୨ৎ────
[ffffff][C][B]
معرفة هل لاعب مبند استعمل:
[00ff00]/🗿check/104[c]145[c]933[c]49
[ffffff]
معرفة سيرفر لاعب استعمل:
[00ff00]/🗿region/104[c]145[c]933[c]49
[ffffff]
زيادة 100 لايك استعمل:
[00ff00]/likes/104[c]145[c]933[c]49
[ffffff]
تحذث معا شات جيبتي استعمل:
[00ff00]/🗿ai [text]
[C][B][69FFB4]────୨ৎ────
[B4FF69]حساب الانستغرام:
[C][b]︱◯֯︱INSTA⤉GRA⤉M┊om1p9
[69FFB4]────୨ৎ────
[C][B][FFA500]
"""
	                time.sleep(1)
	                clients.send(self.GenResponsMsg(response_mssg, uid))
####################################
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
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("")
        payload = payload.replace(b"2024-12-26 13:02:43", str(now).encode())
        payload = payload.replace(b"88332848f415ca9ca98312edcd5fe8bc6547bc6d0477010a7feaf97e3435aa7f", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"e1ccc10e70d823f950f9f4c337d7d20a", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfeMEf", SIGNATURE_MD5.encode("UTF-8"))
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
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": client_secret,"client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "access"
        OLD_OPEN_ID = "openid"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex(paylod_token1)
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
            print(key, iv)
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
            print(f"Token decoded and processed. Account ID: {account_id}")
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
            print("Final token constructed successfully.")
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
    time.sleep(3)
    thread.start()

for thread in threads:
    thread.join()
    
if __name__ == "__main__":
    try:
        client_thread = FF_CLIENT(id="3796034400", password="3CF9F447F04AD2697BMEBB8443E034AB9F17A7C85CFDF14B5B36EF2ED51E8B21")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()
