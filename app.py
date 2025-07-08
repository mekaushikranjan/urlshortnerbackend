from flask import Flask, request, redirect, render_template, send_from_directory, session, jsonify, url_for
from flask_cors import CORS
import hashlib, json, os, time, qrcode
from datetime import datetime
import requests
import uuid
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
CORS(app, supports_credentials=True)

URL_FILE = 'data/urls.json'
ANALYTICS_FILE = 'data/analytics.json'
QR_DIR = 'static/qrcodes'

# Create directories
os.makedirs('data', exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)

load_dotenv()
ADMIN_IPS = os.getenv('ADMIN_IPS').split(',')

# Load or initialize storage
def load_data():
    global url_map, analytics
    url_map = json.load(open(URL_FILE)) if os.path.exists(URL_FILE) else {}
    analytics = json.load(open(ANALYTICS_FILE)) if os.path.exists(ANALYTICS_FILE) else {}

def save_data():
    json.dump(url_map, open(URL_FILE, 'w'), indent=2)
    json.dump(analytics, open(ANALYTICS_FILE, 'w'), indent=2)

load_data()

BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def base62_encode(num):
    if num == 0:
        return BASE62[0]
    s = ""
    while num:
        s = BASE62[num % 62] + s
        num //= 62
    return s

def hash_url(long_url):
    salt = 0
    while True:
        raw = long_url + str(salt)
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        short = base62_encode(int(hashed, 16))[:6]
        if short not in url_map or url_map[short]['original_url'] == long_url:
            return short
        salt += 1

def get_expiration_seconds(option):
    mapping = {
        "5m": 5 * 60,
        "1h": 60 * 60,
        "1d": 24 * 60 * 60,
        "7d": 7 * 24 * 60 * 60,
        "never": None
    }
    return mapping.get(option, None)

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_location(ip):
    try:
        if ip in ['127.0.0.1', '::1', 'localhost']:
            return "Local", "Local", "Local"
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get('status') == 'success':
            region = data.get("regionName", "Unknown")
            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")
            return region, country, city
        return "Unknown", "Unknown", "Unknown"
    except Exception as e:
        print(f"[ERROR] Location fetch failed for IP {ip}: {e}")
        return "Unknown", "Unknown", "Unknown"

def get_device_info(user_agent):
    if not user_agent:
        return "Unknown", "Unknown", "Unknown"
    
    user_agent = user_agent.lower()
    
    # Device detection
    if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
        device = 'Mobile'
    elif 'tablet' in user_agent or 'ipad' in user_agent:
        device = 'Tablet'
    else:
        device = 'Desktop'
    
    # Browser detection
    if 'chrome' in user_agent and 'edg' not in user_agent:
        browser = 'Chrome'
    elif 'firefox' in user_agent:
        browser = 'Firefox'
    elif 'safari' in user_agent and 'chrome' not in user_agent:
        browser = 'Safari'
    elif 'edg' in user_agent:
        browser = 'Edge'
    elif 'opera' in user_agent:
        browser = 'Opera'
    else:
        browser = 'Unknown'
    
    # OS detection
    if 'windows' in user_agent:
        os_name = 'Windows'
    elif 'mac' in user_agent:
        os_name = 'macOS'
    elif 'linux' in user_agent:
        os_name = 'Linux'
    elif 'android' in user_agent:
        os_name = 'Android'
    elif 'ios' in user_agent or 'iphone' in user_agent or 'ipad' in user_agent:
        os_name = 'iOS'
    else:
        os_name = 'Unknown'
    
    return device, browser, os_name

# API Routes
@app.route('/api/shorten', methods=['POST'])
def api_shorten():
    try:
        data = request.get_json()
        long_url = data.get('url')
        custom_alias = data.get('customAlias', '').strip()
        password = data.get('password', '').strip()
        expire_option = data.get('expiration', 'never')
        
        if not long_url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Add protocol if missing
        if not long_url.startswith(('http://', 'https://')):
            long_url = 'https://' + long_url
        
        created_at = time.time()
        expire_at = None if expire_option == 'never' else created_at + get_expiration_seconds(expire_option)
        
        user_id = session.get('user_id')
        if not user_id:
            user_id = str(uuid.uuid4())
            session['user_id'] = user_id
        
        if custom_alias:
            if custom_alias in url_map and url_map[custom_alias]['original_url'] != long_url:
                return jsonify({'error': 'Custom alias already in use'}), 400
            short = custom_alias
        else:
            short = hash_url(long_url)
        
        url_id = str(uuid.uuid4())
        
        url_map[short] = {
            "id": url_id,
            "original_url": long_url,
            "created_at": created_at,
            "expire_at": expire_at,
            "clicks": 0,
            "password": password if password else None,
            "user_id": user_id,
            "custom_alias": custom_alias if custom_alias else None
        }
        
        save_data()
        
        # Generate QR code
        short_url = f"{request.host_url.rstrip('/')}/{short}"
        qr_img = qrcode.make(short_url)
        qr_path = os.path.join(QR_DIR, f"{short}.png")
        qr_img.save(qr_path)
        
        return jsonify({
            'id': url_id,
            'shortUrl': short_url,
            'originalUrl': long_url,
            'customAlias': custom_alias,
            'password': password,
            'expiration': expire_option,
            'createdAt': datetime.fromtimestamp(created_at).isoformat(),
            'clicks': 0,
            'qrCode': f"{request.host_url}static/qrcodes/{short}.png"
        })
        
    except Exception as e:
        print(f"Error in shorten: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/urls', methods=['GET'])
def api_get_urls():
    try:
        user_id = session.get('user_id')
        client_ip = get_client_ip()
        
        if client_ip in ADMIN_IPS:
            visible_urls = url_map
        else:
            visible_urls = {k: v for k, v in url_map.items() if v.get('user_id') == user_id}
        
        urls = []
        for short, data in visible_urls.items():
            urls.append({
                'id': data.get('id', short),
                'shortUrl': f"{request.host_url.rstrip('/')}/{short}",
                'originalUrl': data['original_url'],
                'customAlias': data.get('custom_alias'),
                'password': data.get('password'),
                'expiration': 'never' if not data.get('expire_at') else '1d',  # Simplified
                'createdAt': datetime.fromtimestamp(data['created_at']).isoformat(),
                'clicks': data.get('clicks', 0),
                'qrCode': f"{request.host_url}static/qrcodes/{short}.png"
            })
        
        return jsonify(urls)
        
    except Exception as e:
        print(f"Error in get_urls: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/analytics/<url_id>', methods=['GET'])
def api_get_analytics(url_id):
    try:
        # Find URL by ID
        short_code = None
        for code, data in url_map.items():
            if data.get('id') == url_id:
                short_code = code
                break
        
        if not short_code:
            return jsonify({'error': 'URL not found'}), 404
        
        url_data = url_map[short_code]
        click_logs = analytics.get(short_code, [])
        
        # Process analytics data
        countries = {}
        states = {}
        devices = {}
        browsers = {}
        operating_systems = {}
        referrers = {}
        ip_addresses = []
        click_history = {}
        hourly_stats = [{'hour': i, 'clicks': 0} for i in range(24)]
        
        for log in click_logs:
            # Countries and states
            country = log.get('country', 'Unknown')
            state = log.get('region', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
            states[state] = states.get(state, 0) + 1
            
            # Device info
            user_agent = log.get('user_agent', '')
            device, browser, os_name = get_device_info(user_agent)
            devices[device] = devices.get(device, 0) + 1
            browsers[browser] = browsers.get(browser, 0) + 1
            operating_systems[os_name] = operating_systems.get(os_name, 0) + 1
            
            # Referrers (simplified)
            referrers['Direct'] = referrers.get('Direct', 0) + 1
            
            # IP addresses
            ip = log.get('ip', 'Unknown')
            existing_ip = next((item for item in ip_addresses if item['ip'] == ip), None)
            if existing_ip:
                existing_ip['clicks'] += 1
                existing_ip['lastAccess'] = log.get('timestamp', '')
            else:
                ip_addresses.append({
                    'ip': ip,
                    'country': country,
                    'state': state,
                    'city': log.get('city', 'Unknown'),
                    'clicks': 1,
                    'lastAccess': log.get('timestamp', '')
                })
            
            # Click history by date
            timestamp = log.get('timestamp', '')
            if timestamp:
                try:
                    date = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').date().isoformat()
                    if date not in click_history:
                        click_history[date] = {'date': date, 'clicks': 0, 'uniqueVisitors': 0}
                    click_history[date]['clicks'] += 1
                    click_history[date]['uniqueVisitors'] = len(set(log.get('ip') for log in click_logs if datetime.strptime(log.get('timestamp', ''), '%Y-%m-%d %H:%M:%S').date().isoformat() == date))
                    
                    # Hourly stats
                    hour = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').hour
                    hourly_stats[hour]['clicks'] += 1
                except:
                    pass
        
        analytics_data = {
            'clicks': len(click_logs),
            'uniqueVisitors': len(set(log.get('ip') for log in click_logs)),
            'countries': countries,
            'states': states,
            'devices': devices,
            'browsers': browsers,
            'operatingSystems': operating_systems,
            'referrers': referrers,
            'ipAddresses': ip_addresses[:50],  # Limit to 50 for performance
            'clickHistory': list(click_history.values()),
            'hourlyStats': hourly_stats,
            'dailyStats': list(click_history.values())
        }
        
        return jsonify(analytics_data)
        
    except Exception as e:
        print(f"Error in get_analytics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/urls/<url_id>', methods=['DELETE'])
def api_delete_url(url_id):
    try:
        # Find and delete URL by ID
        short_code = None
        for code, data in url_map.items():
            if data.get('id') == url_id:
                short_code = code
                break
        
        if not short_code:
            return jsonify({'error': 'URL not found'}), 404
        
        # Check ownership
        user_id = session.get('user_id')
        client_ip = get_client_ip()
        
        if client_ip not in ADMIN_IPS and url_map[short_code].get('user_id') != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Delete URL and analytics
        del url_map[short_code]
        if short_code in analytics:
            del analytics[short_code]
        
        # Delete QR code file
        qr_path = os.path.join(QR_DIR, f"{short_code}.png")
        if os.path.exists(qr_path):
            os.remove(qr_path)
        
        save_data()
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error in delete_url: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Redirect route
@app.route('/<short>', methods=['GET', 'POST'])
def redirect_to_original(short):
    entry = url_map.get(short)
    if not entry:
        return jsonify({'error': 'Short URL not found'}), 404

    if entry['expire_at'] and time.time() > entry['expire_at']:
        return jsonify({'error': 'Link expired'}), 410

    qr_code_url = f"{request.host_url.rstrip('/')}" + f"/static/qrcodes/{short}.png"

    if entry.get('password'):
        if request.method == 'POST':
            # Accept JSON or form data
            if request.is_json:
                data = request.get_json()
                user_pass = data.get('password', '') if data else ''
            else:
                user_pass = request.form.get('password', '')
            if user_pass != entry['password']:
                return jsonify({'error': 'Incorrect password'}), 401
            # Password correct: update analytics and redirect
            entry['clicks'] += 1
            save_data()
            ip = get_client_ip()
            region, country, city = get_location(ip)
            user_agent = request.headers.get('User-Agent', '')
            click_info = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "region": region,
                "country": country,
                "city": city,
                "user_agent": user_agent,
                "ip": ip
            }
            analytics.setdefault(short, []).append(click_info)
            save_data()
            return jsonify({'redirectUrl': entry['original_url'], 'qrCode': qr_code_url})
        else:
            # GET: indicate password is required
            return jsonify({'requiresPassword': True, 'qrCode': qr_code_url}), 200

    # No password required: update analytics and redirect
    entry['clicks'] += 1
    save_data()
    ip = get_client_ip()
    region, country, city = get_location(ip)
    user_agent = request.headers.get('User-Agent', '')
    click_info = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "region": region,
        "country": country,
        "city": city,
        "user_agent": user_agent,
        "ip": ip
    }
    analytics.setdefault(short, []).append(click_info)
    save_data()
    return jsonify({'redirectUrl': entry['original_url'], 'qrCode': qr_code_url})

# Static file serving
@app.route('/static/qrcodes/<filename>')
def serve_qr_code(filename):
    return send_from_directory(QR_DIR, filename)

# Health check
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == "__main__":
    app.run(
        host=os.getenv('FLASK_HOST', 'localhost'),
        port=int(os.getenv('FLASK_PORT', 5000)),
        debug=True
    )