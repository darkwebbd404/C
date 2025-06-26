##########BOT-FR-V1-BY-FOX#############
import threading;import jwt;import random;import json;import requests;import google.protobuf;import datetime;from datetime import datetime;import base64;import logging;import re;import socket;import os;import binascii;import sys;import psutil;import time;from time import sleep;from google.protobuf.timestamp_pb2 import Timestamp;from google.protobuf.json_format import MessageToJson;from protobuf_decoder.protobuf_decoder import Parser;from threading import Thread;from Crypto.Cipher import AES;from Crypto.Util.Padding import pad, unpad; import httpx
###########BOT-FR-V1-BY-FOX#############
key = "Fox-7CdxP"
key2 = "projects_xxx_3ei93k_codex_xdfox"
#Get-jwt-token and Updatet in 8h
def get_jwt_token():
    global jwt_token
    url = "https://projects-fox-x-get-jwt.vercel.app/get?uid=3827501129&password=A0381E9D0F8B16B85D5D4F138A5A0DABF5176053A4A958F754DF9BDBAC172A77"
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
#increase-100-visites
def increase_visits(player_id):
    url = f"https://projects-fox-apis.vercel.app/visit?uid={player_id}&key={key}"
    res = requests.get(url)
    if res.status_code == 200:
        print(f"تم زيادة زيارة للحساب {player_id}")
    else:
        print(f"فشل زيادة الزوار للحساب {player_id}")
    time.sleep(0.1)
def increase_visits_threaded(player_id, num_requests=100):
    threads = []
    for _ in range(num_requests):
        thread = threading.Thread(target=increase_visits, args=(player_id,))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    return """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
تم زيادة 100 زيارة للحساب اخرج وادخل مجددا!!

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY CODEX TEAM
       """
#Clan-info-by-clan-id
def Get_clan_info(clan_id):
    try:
        url = f"https://get-clan-info.vercel.app/get_clan_info?clan_id={clan_id}"
        res = requests.get(url)
        if res.status_code == 200:
            data = res.json()
            msg = f""" 
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
▶▶▶▶guild_details◀◀◀◀
achievements: {data['achievements']}\n\n
balance : {fix_num(data['balance'])}\n\n
clan_name : {data['clan_name']}\n\n
expire_time : {fix_num(data['guild_details']['expire_time'])}\n\n
members_online : {fix_num(data['guild_details']['members_online'])}\n\n
regional : {data['guild_details']['regional']}\n\n
reward_time : {fix_num(data['guild_details']['reward_time'])}\n\n
total_members : {fix_num(data['guild_details']['total_members'])}\n\n
id : {fix_num(data['id'])}\n\n
last_active : {fix_num(data['last_active'])}\n\n
level : {fix_num(data['level'])}\n\n
rank : {fix_num(data['rank'])}\n\n
region : {data['region']}\n\n
score : {fix_num(data['score'])}\n\n
timestamp1 : {fix_num(data['timestamp1'])}\n\n
timestamp2 : {fix_num(data['timestamp2'])}\n\n
welcome_message: {data['welcome_message']}\n\n
xp: {fix_num(data['xp'])}\n\n
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY CODEX TEAM
            """
            return msg
        else:
            msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
فشل جلب المعلومات حاول في وقت اخر!!

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY CODEX TEAM
            """
            return msg
    except:
        pass
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
#BOT-PANEL-FOR-CONTROL
def remove_player(player_id):
    url = f"https://projects-fox-apis.vercel.app/remove_friend?token={jwt_token}&id={player_id}&key={key2}"
    res = requests.get(url)
    if res.status_code == 200:
        print('Done')
        data = res.json()
        return data
    else:
        print("fuckkkk")
def adding_player(player_id):
    url = f"https://projects-fox-apis.vercel.app/adding_friend?token={jwt_token}&id={player_id}&key={key2}"
    res = requests.get(url)
    if res.status_code == 200:
        print('Done')
        data = res.json()
        return data
    else:
        print("fuckkkk")
#ADDING-100-LIKES-IN-24H
def get_likes_info(player_id):
    url = f"https://ff-community-api.vercel.app/sendLikes?uid={player_id}&access_key=foxgay"
    res = requests.get(url)
    if res.json().get("success?") is False:
        msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
فشل زيادة لايك حاول بعد مرور 24 ساعة

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY CODEX TEAM
        """
        return msg
    else:
        msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
تم إضافة 100 لايك بنجاح

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY CODEX TEAM
        """
        return msg
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
#SPAM REQUESTS
def spam_requests(player_id):
    url = f"https://spam-fr-lk-team.vercel.app/send_requests?uid={player_id}"
    res = requests.get(url)
    if res.status_code == 200:
        return "Spam is Good"
    else:
        return "fuck spam"
def get_time(uid):
	r = requests.get(f"http://147.93.123.53:50022/get_time/{uid}")
	try:
		response = r
		if "permanent" in response.text:
			time = "Permanent"
			return {"status":"ok","time":time}
		elif "UID not found" in response.text:
			remove_user(uid)
			return {"status":"bad","time":"Expired"}
		else:
			try:
				data = response.json()['remaining_time']
				days = data['days']
				hours = data['hours']
				minutes = data['minutes']
				seconds = data['seconds']
				time = (
				f"{days} Days\n"
				f"{hours} Hours\n"
				f"{minutes} Minutes\n"
				f"{seconds} Seconds\n")
				return {"status":"ok","time":time}
			except Exception as e:
				print(e)
	except Exception as e:
		print(e)
##########BOT-FR-V1-BY-FOX#############
#VARINT ENCRYPT
def Encrypt(number):
    number = int(number)  # تأكد أن المدخل رقم
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes)
def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    elif not isinstance(value, int):
        raise ValueError(f"Value must be integer or numeric string, got {type(value)}")
    return Encrypt(field_header) + Encrypt(value)
def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return Encrypt(field_header) + Encrypt(len(encoded_value)) + encoded_value
def create_protobuf_packet(fields):
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(create_length_delimited_field(field, value))
        else:
            raise TypeError(f"Unsupported type {type(value)} for field {field}")    
    return packet
#GET TIMESTAMP
def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
#Generate Random Color By Fox
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
#ENCODE PACKET
def encrypt_packet(plain_text, key, iv):
    try:
        if not all(c in "0123456789abcdefABCDEF" for c in plain_text):
            raise ValueError("Input contains non-hexadecimal characters")            
        plain_text = bytes.fromhex(plain_text)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        print(f"Error in encrypt_packet: {e}")
        return None
#GET RANDOM AVATAR
def get_random_avatar():
	avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066', 
        '902000074', '902000075', '902000077', '902000078', '902000084', 
        '902000085', '902000087', '902000091', '902000094', '902000306','902000091','902000208','902000209','902000210','902000211','902047016','902047016','902000347'
    ]
	random_avatar = random.choice(avatar_list)
	return  random_avatar
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
##########ALL-PACKET-PROTO-BY-FOX###########
def nmnmmmmn(data, key, iv):
    try:
        key = key if isinstance(key, bytes) else bytes.fromhex(key)
        iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
        data = bytes.fromhex(data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(data, AES.block_size))
        return cipher_text.hex()
    except Exception as e:
        print(f"Error in nmnmmmmn: {e}")
#GARENA PROTO REPLY MSG BY FOX
def GenResponsMsg(Msg, Enc_Id, key, iv):
    fields = {
        1: 1,
        2: {
            1: 657852060,
            2: Enc_Id,
            3: 2,
            4: str(Msg),
            5: int(datetime.now().timestamp()),
            9: {
                1: "FOX",
                2: int(get_random_avatar()),
                4: 330,
                8: "FOX",
                10: 1,
                11: 1
            },
            10: "en",
            13: {3: 1},
            14: ""
        }
    }
    packet = create_protobuf_packet(fields)
    packet = packet.hex()
    header_lenth = len(encrypt_packet(packet, key, iv)) // 2
    header_lenth_final = dec_to_hex(header_lenth)
    prefix = "121500" + "0" * (6 - len(header_lenth_final))
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)    
    return bytes.fromhex(final_packet)
#GARENA PROTO BY FOX
def accept_sq(hashteam, idplayer, ownerr, key, iv):
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
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)   
    return bytes.fromhex(final_packet)
def send_squad(idplayer, key, iv):
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
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)   
    return bytes.fromhex(final_packet)
def invite_skwad(idplayer, key, iv):
    fields = {
        1: 2,
        2: {
            1: int(idplayer),
            2: "ME",
            4: 1
        }
    }
    
    packet = create_protobuf_packet(fields)
    packet = packet.hex()
    header_lenth = len(encrypt_packet(packet, key, iv))//2
    header_lenth_final = dec_to_hex(header_lenth)
    
    prefix = "051500" + "0" * (6 - len(header_lenth_final))
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)
    
    return bytes.fromhex(final_packet)

def skwad_maker(key, iv):
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
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)
    
    return bytes.fromhex(final_packet)

def changes(num, key, iv):
    fields = {
        1: 17,
        2: {
            1: 11155579437,
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
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)
    
    return bytes.fromhex(final_packet)

def leave_s(key, iv):
    fields = {
        1: 7,
        2: {
            1: 11155579437
        }
    }
    
    packet = create_protobuf_packet(fields)
    packet = packet.hex()
    header_lenth = len(encrypt_packet(packet, key, iv))//2
    header_lenth_final = dec_to_hex(header_lenth)
    
    prefix = "051500" + "0" * (6 - len(header_lenth_final))
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)
    
    return bytes.fromhex(final_packet)
   
def request_skwad(idplayer, key, iv):
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
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)
    
    return bytes.fromhex(final_packet)

def start_autooo(key, iv):
    fields = {
        1: 9,
        2: {
            1: 10853443433
        }
    }    
    packet = create_protobuf_packet(fields)
    packet = packet.hex()
    header_lenth = len(encrypt_packet(packet, key, iv))//2
    header_lenth_final = dec_to_hex(header_lenth)    
    prefix = "051500" + "0" * (6 - len(header_lenth_final))
    final_packet = prefix + header_lenth_final + nmnmmmmn(packet, key, iv)   
    return bytes.fromhex(final_packet)
##########BOT-FR-V1-BY-FOX#############
#ALL GARENA PROTO BY FOX!
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_sym_db = _symbol_database.Default()
_globals = globals()
# ============= jwt_generator.proto =============
JWT_GENERATOR_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13jwt_generator.proto\"\xd2\x02\n\nGarena_420\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\r\n\x05place\x18\x03 \x01(\t\x12\x10\n\x08location\x18\x04 \x01(\t\x12\x0e\n\x06status\x18\x05 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\n\n\x02id\x18\t \x01(\x05\x12\x0b\n\x03\x61pi\x18\n \x01(\t\x12\x0e\n\x06number\x18\x0c \x01(\x05\x12\x1e\n\tGarena420\x18\x0f \x01(\x0b\x32\x0b.Garena_420\x12\x0c\n\x04\x61rea\x18\x10 \x01(\t\x12\x11\n\tmain_area\x18\x12 \x01(\t\x12\x0c\n\x04\x63ity\x18\x13 \x01(\t\x12\x0c\n\x04name\x18\x14 \x01(\t\x12\x11\n\ttimestamp\x18\x15 \x01(\x03\x12\x0e\n\x06\x62inary\x18\x16 \x01(\x0c\x12\x13\n\x0b\x62inary_data\x18\x17 \x01(\x0c\x1a\"\n\x12\x44\x65\x63rypted_Payloads\x12\x0c\n\x04type\x18\x01 \x01(\x05\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(JWT_GENERATOR_DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(JWT_GENERATOR_DESCRIPTOR, 'jwt_generator_pb2', _globals)
# ============= Helper =============
class ProtoHelper:
    @staticmethod
    def create_garena_420(**kwargs):
        msg = _globals['Garena_420']()
        for key, value in kwargs.items():
            setattr(msg, key, value)
        return msg
def create_garena_420(**kwargs):
    return ProtoHelper.create_garena_420(**kwargs)
Garena420 = create_garena_420

# ============= MajorLoginRes.proto =============
#MAJOR_LOGIN_RES_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13MajorLoginRes.proto\"\x87\x05\n\rMajorLoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x03\x12\x13\n\x0block_region\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl\x18\t \x01(\x05\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mulator_score\x18\x0c \x01(\x03\x12\x32\n\tblacklist\x18\r \x01(\x0b\x32\x1f.MajorLoginRes.BlacklistInfoRes\x12\x31\n\nqueue_info\x18\x0f \x01(\x0b\x32\x1d.MajorLoginRes.LoginQueueInfo\x12\x0e\n\x06tp_url\x18\x10 \x01(\t\x12\x15\n\rapp_server_id\x18\x11 \x01(\x03\x12\x0f\n\x07\x61no_url\x18\x12 \x01(\t\x12\x0f\n\x07ip_city\x18\x13 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x14 \x01(\t\x12\x0b\n\x03kts\x18\x15 \x01(\x03\x12\n\n\x02\x61k\x18\x16 \x01(\x0c\x12\x0b\n\x03\x61iv\x18\x17 \x01(\x0c\x1aQ\n\x10\x42lacklistInfoRes\x12\x12\n\nban_reason\x18\x01 \x01(\x05\x12\x17\n\x0f\x65xpire_duration\x18\x02 \x01(\x03\x12\x10\n\x08\x62\x61n_time\x18\x03 \x01(\x03\x1a\x66\n\x0eLoginQueueInfo\x12\r\n\x05\x41llow\x18\x01 \x01(\x08\x12\x16\n\x0equeue_position\x18\x02 \x01(\x03\x12\x16\n\x0eneed_wait_secs\x18\x03 \x01(\x03\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08\x62\x06proto3')
#_builder.BuildMessageAndEnumDescriptors(MAJOR_LOGIN_RES_DESCRIPTOR, _globals)
#_builder.BuildTopDescriptorsAndMessages(MAJOR_LOGIN_RES_DESCRIPTOR, 'MajorLoginRes_pb2', _globals)
#class ProtoHelper:
#    @staticmethod
#    def create_major_login_res(**kwargs):
#        msg = _globals['MajorLoginRes']()
#        for key, value in kwargs.items():
#            setattr(msg, key, value)
#        return msg
#def create_major_login_res(**kwargs):
#    return ProtoHelper.create_major_login_res(**kwargs)
#MajorLoginRes = create_major_login_res