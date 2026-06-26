from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
import time
from collections import defaultdict
import random
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import jwt
import threading

app = Flask(__name__)

# ============ CONFIG ============
MAX_CONCURRENT = 50
REFRESH_INTERVAL = 6300  # 1 ঘন্টা 45 মিনিট
TOKEN_REFRESH_TIMEOUT = 5  # 🔥 প্রতিটি টোকেন রিফ্রেশের সময় ১০ সেকেন্ড
REQUEST_TIMEOUT = 5
GLOBAL_REFRESH_LOCK = threading.Lock()
MAX_ACCOUNTS_PER_REQUEST = 220

# ============ GLOBAL STATE ============
account_cache = {}
liked_cache = defaultdict(set)
token_cache = {}  # {uid: (token, timestamp)}
token_refresh_tracker = {}  # 🔥 {uid: last_refresh_time}
last_global_refresh = 0
executor = ThreadPoolExecutor(max_workers=50)

# ============ FILE CONFIG ============
FILE_CONFIG = {
    'BD': 'shappno_bd.txt',
    'ID': 'shappno_bd.txt',
    'ME': 'shappno_bd.txt',
    'RU': 'shappno_bd.txt',
    'EU': 'shappno_bd.txt',
    'IND': 'shappno_ind.txt'
}

# ============ TOKEN FUNCTIONS ============
def is_token_expired(token):
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        exp = payload.get('exp', 0)
        if exp == 0:
            return True
        return time.time() > (exp - 60)
    except:
        return True

def refresh_token_sync(uid, password):
    """একটা অ্যাকাউন্টের টোকেন রিফ্রেশ করো"""
    try:
        encoded_password = urllib.parse.quote(password)
        url = f"http://shappno-jwt-api-ob54.vercel.app/token?uid={uid}&password={encoded_password}"
        response = requests.get(url, timeout=TOKEN_REFRESH_TIMEOUT)  # 🔥 ১০ সেকেন্ড
        if response.status_code == 200:
            data = response.json()
            token = data.get('token')
            if token:
                print(f"✅ Token refreshed for {uid}")
                return token
    except Exception as e:
        print(f"❌ Refresh failed for {uid}: {e}")
    return None

def get_valid_token(account):
    """
    🔥 টোকেন ভালো থাকলে রিটার্ন করো
    ❌ মেয়াদ শেষ হলে রিফ্রেশ করো
    """
    uid = account['uid']
    
    # ক্যাশে আছে কিনা চেক করো
    if uid in token_cache:
        token, timestamp = token_cache[uid]
        if not is_token_expired(token):
            # ✅ টোকেন ভালো আছে
            return token
    
    # ❌ টোকেন মেয়াদ শেষ! এখনই রিফ্রেশ করো
    if account.get('password'):
        print(f"🔄 Refreshing expired token for {uid}...")
        new_token = refresh_token_sync(uid, account['password'])
        if new_token:
            token_cache[uid] = (new_token, time.time())
            token_refresh_tracker[uid] = time.time()  # 🔥 ট্র্যাক করো কখন রিফ্রেশ হলো
            account['token'] = new_token
            account['is_token'] = True
            return new_token
        else:
            print(f"❌ Could not refresh token for {uid}")
    
    return None

def refresh_all_tokens_sync():
    """🔥 প্রতি ১ ঘন্টা ৪৫ মিনিটে সব টোকেন রিফ্রেশ করো"""
    global last_global_refresh
    
    with GLOBAL_REFRESH_LOCK:
        current_time = time.time()
        if current_time - last_global_refresh < REFRESH_INTERVAL:
            return {'status': 'skipped', 'message': f'Next refresh in {int(REFRESH_INTERVAL - (current_time - last_global_refresh))}s'}
        
        print("🔄 Refreshing ALL tokens (1h 45m timer)...")
        
        all_accounts = []
        for file_name in ['shappno_bd.txt', 'shappno_ind.txt']:
            if os.path.exists(file_name):
                accounts = load_accounts_from_file(file_name)
                all_accounts.extend(accounts)
        
        refreshed = 0
        failed = 0
        new_tokens = {}
        
        with ThreadPoolExecutor(max_workers=50) as exec:
            futures = {}
            for account in all_accounts:
                if account.get('password'):
                    future = exec.submit(refresh_token_sync, account['uid'], account['password'])
                    futures[future] = account['uid']
            
            for future in as_completed(futures):
                uid = futures[future]
                try:
                    new_token = future.result(timeout=TOKEN_REFRESH_TIMEOUT + 2)
                    if new_token:
                        token_cache[uid] = (new_token, time.time())
                        token_refresh_tracker[uid] = time.time()
                        new_tokens[uid] = new_token
                        refreshed += 1
                    else:
                        failed += 1
                except:
                    failed += 1
        
        if new_tokens:
            save_tokens_to_files(new_tokens)
        
        last_global_refresh = time.time()
        print(f"✅ Global refresh: {refreshed} refreshed, {failed} failed")
        
        return {
            'status': 'completed', 
            'refreshed': refreshed, 
            'failed': failed,
            'total': len(all_accounts)
        }

# ============ LOAD ACCOUNTS ============
def load_accounts_from_file(filename):
    accounts = []
    if not os.path.exists(filename):
        print(f"⚠️ {filename} not found!")
        return []
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                parts = line.split(':', 1)
                uid = parts[0].strip()
                value = parts[1].strip()
                if uid and value:
                    if '.' in value and len(value) > 50:
                        accounts.append({"uid": uid, "token": value, "is_token": True})
                        token_cache[uid] = (value, time.time())
                    else:
                        accounts.append({"uid": uid, "password": value, "is_token": False})
    
    print(f"📁 Loaded {len(accounts)} accounts from {filename}")
    return accounts

def load_accounts_for_region(server_name):
    filename = FILE_CONFIG.get(server_name, 'shappno_bd.txt')
    cache_key = f"accounts_{filename}"
    if cache_key in account_cache:
        return account_cache[cache_key]
    accounts = load_accounts_from_file(filename)
    account_cache[cache_key] = accounts
    return accounts

# ============ SAVE TOKENS ============
def save_tokens_to_files(tokens):
    try:
        bd_tokens = {}
        ind_tokens = {}
        
        bd_accounts = load_accounts_from_file('shappno_bd.txt') if os.path.exists('shappno_bd.txt') else []
        ind_accounts = load_accounts_from_file('shappno_ind.txt') if os.path.exists('shappno_ind.txt') else []
        
        bd_uids = {acc['uid'] for acc in bd_accounts}
        ind_uids = {acc['uid'] for acc in ind_accounts}
        
        for uid, token in tokens.items():
            if uid in bd_uids:
                bd_tokens[uid] = token
            elif uid in ind_uids:
                ind_tokens[uid] = token
            else:
                bd_tokens[uid] = token
        
        if bd_tokens:
            update_file_with_tokens('shappno_bd.txt', bd_tokens)
        if ind_tokens:
            update_file_with_tokens('shappno_ind.txt', ind_tokens)
        return True
    except Exception as e:
        print(f"❌ Save error: {e}")
        return False

def update_file_with_tokens(filename, tokens):
    try:
        lines = []
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                lines = f.readlines()
        
        updated_uids = set()
        new_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            if line_stripped and ':' in line_stripped:
                uid = line_stripped.split(':', 1)[0].strip()
                if uid in tokens:
                    new_lines.append(f"{uid}:{tokens[uid]}\n")
                    updated_uids.add(uid)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        
        for uid, token in tokens.items():
            if uid not in updated_uids:
                new_lines.append(f"{uid}:{token}\n")
        
        with open(filename, 'w') as f:
            f.writelines(new_lines)
        return True
    except Exception as e:
        print(f"❌ Update error: {e}")
        return False

# ============ ENCRYPTION ============
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return binascii.hexlify(cipher.encrypt(padded_message)).decode('utf-8')

def create_protobuf_message(user_id, region):
    message = like_pb2.like()
    message.uid = int(user_id)
    message.region = region
    return message.SerializeToString()

def enc(uid):
    message = uid_generator_pb2.uid_generator()
    message.krishna_ = int(uid)
    message.teamXdarks = 1
    return encrypt_message(message.SerializeToString())

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except:
        return None

# ============ PLAYER INFO ============
def get_player_info_sync(encrypted_uid, server_name, token):
    if server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

    edata = bytes.fromhex(encrypted_uid)
    headers = {
         'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
         'Authorization': f"Bearer {token}",
         'Content-Type': "application/x-www-form-urlencoded",
         'X-GA': "v1 1",
         'ReleaseVersion': "OB54"
    }

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=REQUEST_TIMEOUT)
        return decode_protobuf(response.content)
    except:
        return None

# ============ SEND LIKE ============
def send_like_sync(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54"
        }
        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=REQUEST_TIMEOUT)
        return response.status_code
    except:
        return 500

def process_account_sync(target_uid, encrypted_uid, account, url):
    account_key = f"{account['uid']}:{target_uid}"
    
    # ইতিমধ্যে লাইক দিয়েছে কিনা চেক করো
    if account_key in liked_cache[target_uid]:
        return 0, account['uid']
    
    # 🔥 টোকেন ভালো আছে কিনা চেক করো, না থাকলে রিফ্রেশ করো
    token = get_valid_token(account)
    if not token:
        print(f"❌ No token for {account['uid']}")
        return 500, account['uid']
    
    # লাইক পাঠাও
    status = send_like_sync(encrypted_uid, token, url)
    
    if status == 200:
        liked_cache[target_uid].add(account_key)
        print(f"✅ {account['uid']} liked successfully")
        return status, account['uid']
    else:
        print(f"❌ {account['uid']} failed with status {status}")
        return status, account['uid']

def send_all_likes_sync(target_uid, server_name, url):
    region = server_name
    protobuf_message = create_protobuf_message(target_uid, region)
    encrypted_uid = encrypt_message(protobuf_message)
    
    accounts = load_accounts_for_region(server_name)
    if not accounts:
        return {'success': 0, 'failed': 0, 'total': 0}
    
    already_liked = liked_cache.get(target_uid, set())
    fresh_accounts = [acc for acc in accounts if f"{acc['uid']}:{target_uid}" not in already_liked]
    
    if not fresh_accounts:
        print(f"⚠️ No fresh accounts for {target_uid}")
        return {'success': 0, 'failed': 0, 'total': len(accounts), 'already_liked': len(already_liked), 'fresh_used': 0}
    
    random.shuffle(fresh_accounts)
    fresh_accounts = fresh_accounts[:MAX_ACCOUNTS_PER_REQUEST]
    
    print(f"📤 Sending likes from {len(fresh_accounts)} accounts...")
    
    results = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        futures = {executor.submit(process_account_sync, target_uid, encrypted_uid, acc, url): acc for acc in fresh_accounts}
        
        for future in as_completed(futures):
            try:
                result = future.result(timeout=REQUEST_TIMEOUT + 3)
                results.append(result)
            except Exception as e:
                print(f"⚠️ Future error: {e}")
                results.append((500, 'unknown'))
    
    successful = sum(1 for status, _ in results if status == 200)
    failed = sum(1 for status, _ in results if status != 0 and status != 200)
    
    print(f"✅ Successful: {successful}, Failed: {failed}")
    
    return {
        'success': successful,
        'failed': failed,
        'total': len(accounts),
        'already_liked': len(already_liked),
        'fresh_used': len(fresh_accounts)
    }

# ============ ROUTES ============
@app.route('/like', methods=['GET'])
def handle_requests():
    start_time = time.time()
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name required"}), 400

    valid_servers = ["IND", "BD", "ID", "ME", "RU", "EU", "BR", "US", "SAC", "NA"]
    if server_name not in valid_servers:
        return jsonify({"error": f"Invalid server. Use: {valid_servers}"}), 400

    print(f"📥 Request: UID={uid}, Server={server_name}")

    # 🔥 ১ ঘন্টা ৪৫ মিনিট পর সব টোকেন রিফ্রেশ
    global last_global_refresh
    current_time = time.time()
    if current_time - last_global_refresh >= REFRESH_INTERVAL:
        refresh_result = refresh_all_tokens_sync()
        print(f"🔄 Global refresh result: {refresh_result}")

    accounts = load_accounts_for_region(server_name)
    if not accounts:
        return jsonify({"error": "No accounts found for this region"}), 500
    
    # চেক করার জন্য একটা ভালো টোকেন নাও
    check_token = None
    for account in accounts:
        token = get_valid_token(account)
        if token:
            check_token = token
            break
    
    if not check_token:
        return jsonify({"error": "No valid token found"}), 500
    
    encrypted_uid = enc(uid)

    # আগের লাইক কাউন্ট
    try:
        before = get_player_info_sync(encrypted_uid, server_name, check_token)
        if before is None:
            return jsonify({"error": "Invalid UID or server", "status": 0}), 200
        
        before_data = json.loads(MessageToJson(before))
        before_like = int(before_data['AccountInfo'].get('Likes', 0))
        print(f"📊 Before likes: {before_like}")
    except Exception as e:
        print(f"❌ Before error: {e}")
        return jsonify({"error": "Data parsing failed", "status": 0}), 200
    
    # লাইক URL
    if server_name == "IND":
        like_url = "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        like_url = "https://client.us.freefiremobile.com/LikeProfile"
    else:
        like_url = "https://clientbp.ggpolarbear.com/LikeProfile"

    print(f"📤 Sending likes to {like_url}")
    result = send_all_likes_sync(uid, server_name, like_url)

    # পরে লাইক কাউন্ট
    try:
        after = get_player_info_sync(encrypted_uid, server_name, check_token)
        if after is None:
            return jsonify({"error": "Could not verify likes", "status": 0}), 200
        
        after_data = json.loads(MessageToJson(after))
        after_like = int(after_data['AccountInfo']['Likes'])
        player_id = int(after_data['AccountInfo']['UID'])
        player_name = str(after_data['AccountInfo']['PlayerNickname'])
        
        like_given = after_like - before_like
        status = 1 if like_given != 0 else 2

        elapsed = time.time() - start_time
        
        print(f"✅ Done! Likes given: {like_given}, Time: {elapsed:.2f}s")
        
        return jsonify({
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "UID": player_id,
            "status": status,
            "accounts_used": result.get('fresh_used', 0),
            "successful_likes": result.get('success', 0),
            "total_accounts": result.get('total', 0),
            "already_liked": result.get('already_liked', 0),
            "time_taken": f"{elapsed:.2f} seconds",
            "refresh_status": "Auto on expiry + 1h 45m timer",
            "token_refresh_timeout": f"{TOKEN_REFRESH_TIMEOUT}s per account"
        })
    except Exception as e:
        print(f"❌ After error: {e}")
        return jsonify({"error": str(e), "status": 0}), 500

@app.route('/refresh', methods=['GET'])
def manual_refresh():
    """ম্যানুয়ালি সব টোকেন রিফ্রেশ করো"""
    result = refresh_all_tokens_sync()
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health():
    bd_accounts = load_accounts_from_file('shappno_bd.txt') if os.path.exists('shappno_bd.txt') else []
    ind_accounts = load_accounts_from_file('shappno_ind.txt') if os.path.exists('shappno_ind.txt') else []
    
    valid_tokens = 0
    expired_tokens = 0
    for uid in token_cache:
        token, _ = token_cache[uid]
        if not is_token_expired(token):
            valid_tokens += 1
        else:
            expired_tokens += 1
    
    return jsonify({
        "status": "healthy",
        "accounts": {
            "bd_file": len(bd_accounts),
            "ind_file": len(ind_accounts),
            "total": len(bd_accounts) + len(ind_accounts)
        },
        "token_cache": len(token_cache),
        "valid_tokens": valid_tokens,
        "expired_tokens": expired_tokens,
        "last_global_refresh": time.ctime(last_global_refresh),
        "next_global_refresh_in": max(0, int(REFRESH_INTERVAL - (time.time() - last_global_refresh))),
        "token_refresh_timeout": f"{TOKEN_REFRESH_TIMEOUT}s per account",
        "concurrent_workers": MAX_CONCURRENT,
        "max_accounts_per_request": MAX_ACCOUNTS_PER_REQUEST,
        "refresh_logic": "On expiry + Every 1h 45m"
    })

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "name": "SHAPPNO API V3 - SMART REFRESH",
        "version": "3.6",
        "features": [
            "⚡ Auto token refresh on expiry (per account)",
            "🔄 All tokens refresh every 1h 45m",
            "📦 Max 220 accounts per request",
            "🌍 Multi-region support",
            "📁 Separate account files",
            "🔍 Debug logging enabled",
            f"⏱️ {TOKEN_REFRESH_TIMEOUT}s per token refresh"
        ],
        "performance": {
            "max_concurrent": 50,
            "max_accounts_per_request": 220,
            "token_refresh_timeout": f"{TOKEN_REFRESH_TIMEOUT}s",
            "global_refresh_interval": "1h 45m"
        },
        "endpoints": {
            "/like": "Send likes (uid & server_name required)",
            "/refresh": "Manually refresh ALL tokens",
            "/health": "Check API status"
        },
        "credit": "@SHAPPNO"
    })

if __name__ == '__main__':
    print("🚀 SHAPPNO API V3 - SMART REFRESH Started!")
    print(f"⚡ Max concurrent: {MAX_CONCURRENT}")
    print(f"📦 Max accounts per request: {MAX_ACCOUNTS_PER_REQUEST}")
    print(f"⏱️ Token refresh timeout: {TOKEN_REFRESH_TIMEOUT}s per account")
    print(f"🔄 Refresh logic: On expiry + Every 1h 45m")
    print(f"📁 Files: shappno_bd.txt, shappno_ind.txt")
    app.run(host='0.0.0.0', port=5001, debug=False)