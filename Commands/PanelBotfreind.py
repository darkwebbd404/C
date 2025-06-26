import telebot
import requests
import time

bot = telebot.TeleBot("7867498989:AAHurrsihsoffIK-w3Ggkf2Vm2I5ECApTNs")
ALLOWED_GROUP_ID = --1002362608483
API_BASE = "http://69.62.118.127:4001"

def add_player(player_id):
    url = f"{API_BASE}/add_uid?uid={player_id}&time=86400&type=seconds"
    try:
        res = requests.get(url, timeout=5)
        return res.status_code == 200
    except:
        return False

def get_remaining_time(player_id):
    url = f"{API_BASE}/get_time/{player_id}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            return res.json()
        return None
    except:
        return None

@bot.message_handler(commands=['add'])
def handle_add(message):
    if message.chat.id != ALLOWED_GROUP_ID:
        return
    
    try:
        player_id = message.text.split()[1]
        if add_player(player_id):
            time_data = get_remaining_time(player_id)
            if time_data:
                remaining = time_data['remaining_time']
                response = (
                    f"✅ تمت إضافة اللاعب {player_id}\n"
                    f"⏳ الوقت المتبقي:\n"
                    f"الأيام: {remaining['days']}\n"
                    f"الساعات: {remaining['hours']}\n"
                    f"الدقائق: {remaining['minutes']}\n"
                    f"الثواني: {remaining['seconds']}"
                )
            else:
                response = f"✅ تمت إضافة اللاعب {player_id} لمدة 24 ساعة"
            bot.reply_to(message, response)
        else:
            bot.reply_to(message, f"❌ فشل في إضافة اللاعب {player_id}")
    except:
        bot.reply_to(message, "استخدم: /add <uid>")

while True:
    try:
        bot.polling(none_stop=True, interval=2, timeout=30)
    except Exception as e:
        print(f"حدث خطأ: {e}")
        time.sleep(10)