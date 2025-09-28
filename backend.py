# -*- coding: utf-8 -*-
import os
import sqlite3
import secrets
import string
import threading
import time
import re
import hashlib
import hmac
import jwt
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS

# Gmail API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle

class MultiAccountSecureSystem:
    """Çoklu Gmail hesabı + email filter sistemi"""
    
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
    def __init__(self):
        # Güvenlik ayarları
        self.SECRET_KEY = os.getenv('SECRET_KEY', 'multi-account-secure-key-2025')
        self.config_file = 'multi_account_config.json'
        self.load_or_create_admin_config()
        
        self.db_path = 'multi_account_system.db'
        self.scanning_active = False
        self.scan_thread = None
        self.gmail_services = {}  # Account ID -> Gmail service
        self.last_message_ids = {}  # Account ID + Filter ID -> Last message ID
        self.system_start_time = datetime.now()
        self.init_db()
        
        print("🚀 Çoklu Gmail hesabı sistemi başlatıldı")
        print(f"📧 Config: {self.config_file}")
    
    def load_or_create_admin_config(self):
        """Admin config dosyasını yükle veya oluştur"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.admin_config = json.load(f)
                print(f"✅ Multi account config yüklendi: {self.config_file}")
            else:
                # Varsayılan config oluştur
                self.admin_config = {
                    "admin_password": "Zort123.",
                    "gmail_accounts": [
                        {
                            "id": "account_1",
                            "name": "Ana Gmail Hesabı",
                            "email": "your-gmail@gmail.com",
                            "credentials_file": "credentials.json",
                            "token_file": "token.pickle",
                            "active": True
                        }
                    ],
                    "email_filters": [
                        {
                            "id": "hbo_filter",
                            "name": "HBO Max Kodları",
                            "account_id": "account_1",
                            "from_email": "no-reply@message.hbomax.com",
                            "trigger_phrases": ["Tek Seferlik Kodunuz"],
                            "code_patterns": [
                                r'(?is)tek\s*seferlik\s*kodunuz\s*[:：-]?\s*(?:<br\s*/?>|\r?\n)+\s*(\d{6})',
                                r'(\d{6})'
                            ],
                            "active": True
                        },
                        {
                            "id": "netflix_filter",
                            "name": "Netflix Kodları",
                            "account_id": "account_1", 
                            "from_email": "info@account.netflix.com",
                            "trigger_phrases": ["Oturum açmak için aşağıdaki kodu girin"],
                            "code_patterns": [
                                r'(?is)oturum\s*açmak\s*için\s*aşağıdaki\s*kodu\s*gir(?:in|iniz)\s*[:：-]?\s*(?:<br\s*/?>|\r?\n)+\s*(\d{4})',
                                r'(\d{4})'
                            ],
                            "active": True
                        }
                    ]
                }
                self.save_admin_config()
                print("🆕 Varsayılan multi account config oluşturuldu")
        except Exception as e:
            print(f"❌ Config yükleme hatası: {e}")
            self.admin_config = {
                "admin_password": "Zort123.",
                "gmail_accounts": [],
                "email_filters": []
            }
    
    def save_admin_config(self):
        """Admin config dosyasını kaydet"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.admin_config, f, indent=2, ensure_ascii=False)
            print("💾 Multi account config kaydedildi")
        except Exception as e:
            print(f"❌ Config kaydetme hatası: {e}")
    
    def get_admin_password_hash(self):
        """Admin şifresinin güvenli hash'ini oluştur"""
        password = self.admin_config.get("admin_password", "Zort123.")
        salt = b"multi_account_salt_2025"
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return password_hash.hex()
    
    def verify_admin_password(self, password):
        """Admin şifresini doğrula"""
        if not password:
            return False
        
        salt = b"multi_account_salt_2025"
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        expected_hash = self.get_admin_password_hash()
        return hmac.compare_digest(password_hash.hex(), expected_hash)
    
    def update_admin_password(self, new_password):
        """Admin şifresini güncelle"""
        self.admin_config["admin_password"] = new_password
        self.save_admin_config()
        print("🔐 Admin şifresi güncellendi")
    
    def generate_admin_token(self):
        """Admin için JWT token oluştur"""
        payload = {
            'role': 'admin',
            'exp': datetime.utcnow() + timedelta(hours=8),
            'iat': datetime.utcnow()
        }
        token = jwt.encode(payload, self.SECRET_KEY, algorithm='HS256')
        # JWT v2.x compatibility
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token
    
    def verify_admin_token(self, token):
        """Admin JWT token'ını doğrula"""
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=['HS256'])
            return payload.get('role') == 'admin'
        except jwt.ExpiredSignatureError:
            print("🔒 Admin token süresi dolmuş")
            return False
        except jwt.InvalidTokenError:
            print("🔒 Geçersiz admin token")
            return False
    
    def init_db(self):
        """Veritabanı başlat"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Kullanıcı tablosu - account_id ve filter_id eklendi
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_key TEXT PRIMARY KEY,
                account_id TEXT DEFAULT 'account_1',
                filter_id TEXT DEFAULT 'hbo_filter',
                has_code INTEGER DEFAULT 0,
                received_code TEXT,
                created_date TEXT,
                code_received_date TEXT,
                created_by_admin TEXT DEFAULT 'admin'
            )
        ''')
        
        # Sistem durumu tablosu - account_id + filter_id kombinasyonu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_status (
                account_filter_id TEXT PRIMARY KEY,
                account_id TEXT,
                filter_id TEXT,
                current_code TEXT,
                last_message_id TEXT,
                last_check TEXT
            )
        ''')
        
        # Admin oturumları tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_id TEXT PRIMARY KEY,
                created_date TEXT,
                expires_date TEXT,
                active INTEGER DEFAULT 1
            )
        ''')
        
        # Normal admin kullanıcısı
        cursor.execute('INSERT OR IGNORE INTO users VALUES ("admin", "system", "admin", 0, NULL, ?, NULL, "system")', 
                      (datetime.now().isoformat(),))
        
        # Her account + filter kombinasyonu için sistem durumu
        for account in self.admin_config.get("gmail_accounts", []):
            for email_filter in self.admin_config.get("email_filters", []):
                if email_filter.get("account_id") == account["id"]:
                    account_filter_id = f"{account['id']}_{email_filter['id']}"
                    cursor.execute('''INSERT OR IGNORE INTO system_status 
                                     (account_filter_id, account_id, filter_id, current_code, last_message_id, last_check)
                                     VALUES (?, ?, ?, NULL, NULL, ?)''', 
                                  (account_filter_id, account["id"], email_filter["id"], datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        print("✅ Çoklu hesap veritabanı hazır")
    
    def add_gmail_account(self, account_config):
        """Yeni Gmail hesabı ekle"""
        # Unique ID oluştur
        account_id = account_config.get("id") or f"account_{int(time.time())}"
        account_config["id"] = account_id
        
        # Varsayılanlar
        account_config.setdefault("active", True)
        account_config.setdefault("credentials_file", f"credentials_{account_id}.json")
        account_config.setdefault("token_file", f"token_{account_id}.pickle")
        
        # Hesaplara ekle
        self.admin_config.setdefault("gmail_accounts", []).append(account_config)
        self.save_admin_config()
        
        print(f"📧 Yeni Gmail hesabı eklendi: {account_config['name']} ({account_id})")
        return account_id
    
    def update_gmail_account(self, account_id, updates):
        """Gmail hesabını güncelle"""
        accounts = self.admin_config.get("gmail_accounts", [])
        for i, account in enumerate(accounts):
            if account["id"] == account_id:
                accounts[i].update(updates)
                self.save_admin_config()
                print(f"📧 Gmail hesabı güncellendi: {account_id}")
                return True
        return False
    
    def delete_gmail_account(self, account_id):
        """Gmail hesabını sil"""
        accounts = self.admin_config.get("gmail_accounts", [])
        new_accounts = [acc for acc in accounts if acc["id"] != account_id]
        
        if len(new_accounts) != len(accounts):
            self.admin_config["gmail_accounts"] = new_accounts
            
            # Bu hesaba bağlı filtreleri de sil
            filters = self.admin_config.get("email_filters", [])
            new_filters = [f for f in filters if f.get("account_id") != account_id]
            self.admin_config["email_filters"] = new_filters
            
            self.save_admin_config()
            
            # DB'den de sil
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM system_status WHERE account_id = ?', (account_id,))
            conn.commit()
            conn.close()
            
            print(f"🗑️ Gmail hesabı silindi: {account_id}")
            return True
        return False
    
    def create_user_key(self, account_id, filter_id):
        """Yeni kullanıcı anahtarı oluştur - belirli account + filter için"""
        while True:
            key = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(3)) + \
                  ''.join(secrets.choice(string.digits) for _ in range(5))
            key = key.lower()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT user_key FROM users WHERE user_key = ?', (key,))
            if not cursor.fetchone():
                cursor.execute('INSERT INTO users VALUES (?, ?, ?, 0, NULL, ?, NULL, ?)', 
                              (key, account_id, filter_id, datetime.now().isoformat(), "admin"))
                conn.commit()
                conn.close()
                print(f"🔑 Yeni anahtar oluşturuldu: {key} (account: {account_id}, filter: {filter_id})")
                return key.upper()
            conn.close()
    
    def get_user(self, key):
        """Kullanıcı bilgisi al"""
        key = str(key).lower().strip()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE user_key = ?', (key,))
        user = cursor.fetchone()
        conn.close()
        return user
    
    def assign_code_to_user(self, user_key):
        """Kodu kullanıcıya ata - account + filter bazlı"""
        user_key = str(user_key).lower().strip()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Kullanıcıyı al
        cursor.execute('SELECT * FROM users WHERE user_key = ?', (user_key,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"error": "Geçersiz kullanıcı anahtarı"}
        
        user_account_id = user[1]  # account_id
        user_filter_id = user[2]   # filter_id
        
        # Zaten kod aldı mı?
        if user[3]:  # has_code
            conn.close()
            return {
                "success": True, 
                "code": user[4], 
                "message": "Zaten kodunuz var",
                "already_received": True
            }
        
        # Bu account + filter kombinasyonu için sistem kodunu al
        account_filter_id = f"{user_account_id}_{user_filter_id}"
        cursor.execute('SELECT current_code FROM system_status WHERE account_filter_id = ?', (account_filter_id,))
        system_code = cursor.fetchone()
        
        if not system_code or not system_code[0]:
            conn.close()
            return {"success": True, "code": None, "message": f"Bu hesap/filter ({user_account_id}/{user_filter_id}) için yeni kod bekleniyor..."}
        
        # Kodu kullanıcıya ver
        current_time = datetime.now().isoformat()
        cursor.execute('''UPDATE users 
                         SET has_code = 1, received_code = ?, code_received_date = ? 
                         WHERE user_key = ?''',
                      (system_code[0], current_time, user_key))
        
        # Sistem kodunu sıfırla (tek kullanım)
        cursor.execute('UPDATE system_status SET current_code = NULL WHERE account_filter_id = ?', (account_filter_id,))
        
        conn.commit()
        conn.close()
        
        print(f"🎁 Kod verildi: {user_key} → {system_code[0]} (account/filter: {user_account_id}/{user_filter_id})")
        return {
            "success": True, 
            "code": system_code[0], 
            "message": "Kodunuz atandı!",
            "assigned_date": current_time,
            "account_id": user_account_id,
            "filter_id": user_filter_id
        }
    
    def authenticate_gmail_account(self, account_id):
        """Belirli Gmail hesabı için API kimlik doğrulaması"""
        account = None
        for acc in self.admin_config.get("gmail_accounts", []):
            if acc["id"] == account_id:
                account = acc
                break
        
        if not account:
            raise Exception(f"Account bulunamadı: {account_id}")
        
        credentials_file = account.get("credentials_file", "credentials.json")
        token_file = account.get("token_file", "token.pickle")
        
        print(f"📧 Gmail API bağlantısı: {account['name']} ({account_id})")
        creds = None
        
        if os.path.exists(token_file):
            with open(token_file, 'rb') as token:
                creds = pickle.load(token)
                print(f"📁 Mevcut token: {token_file}")
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                print(f"🔄 Token yenileniyor: {account_id}")
                creds.refresh(Request())
            else:
                if not os.path.exists(credentials_file):
                    raise FileNotFoundError(f"❌ {credentials_file} bulunamadı!")
                
                print(f"🔐 Yeni kimlik doğrulaması: {account_id}")
                flow = InstalledAppFlow.from_client_secrets_file(credentials_file, self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            with open(token_file, 'wb') as token:
                pickle.dump(creds, token)
                print(f"💾 Token kaydedildi: {token_file}")
        
        service = build('gmail', 'v1', credentials=creds)
        self.gmail_services[account_id] = service
        print(f"✅ Gmail API bağlandı: {account['name']}")
        return True
    
    def authenticate_all_accounts(self):
        """Tüm aktif Gmail hesaplarını bağla"""
        success_count = 0
        for account in self.admin_config.get("gmail_accounts", []):
            if account.get("active", True):
                try:
                    self.authenticate_gmail_account(account["id"])
                    success_count += 1
                except Exception as e:
                    print(f"❌ {account['name']} bağlantı hatası: {e}")
        
        print(f"📧 {success_count} Gmail hesabı bağlandı")
        return success_count > 0
    
    def detect_code_from_content(self, content, email_filter):
        """İçerikten kod tespit et - filter bazlı"""
        # Tetikleyici kelimeleri kontrol et
        trigger_found = False
        for trigger in email_filter["trigger_phrases"]:
            if trigger.lower() in content.lower():
                trigger_found = True
                print(f"🎯 Tetikleyici bulundu: '{trigger}'")
                break
        
        if not trigger_found:
            return None
        
        # Kod pattern'leri dene
        for pattern in email_filter["code_patterns"]:
            try:
                match = re.search(pattern, content, re.IGNORECASE | re.UNICODE | re.DOTALL)
                if match:
                    code = match.group(1) if match.groups() else match.group(0)
                    # Boşlukları kaldır
                    code = re.sub(r'\s+', '', code)
                    print(f"✅ Kod bulundu: {code}")
                    return code
            except Exception as e:
                print(f"❌ Pattern hatası: {pattern} - {e}")
                continue
        
        print("❌ Tetikleyici var ama kod bulunamadı")
        return None
    
    def get_message_text(self, payload):
        """Mesajın düz metin içeriğini al"""
        def extract_text_from_part(part):
            if part.get('mimeType') == 'text/plain':
                data = part['body'].get('data')
                if data:
                    import base64
                    try:
                        return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    except:
                        return ""
            elif part.get('mimeType') == 'text/html':
                data = part['body'].get('data')
                if data:
                    import base64
                    try:
                        return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    except:
                        return ""
            elif part.get('parts'):
                result = ""
                for sub_part in part['parts']:
                    result += extract_text_from_part(sub_part)
                return result
            return ""
        
        text_content = ""
        if 'parts' in payload:
            for part in payload['parts']:
                text_content += extract_text_from_part(part)
        else:
            if payload.get('mimeType') in ['text/plain', 'text/html']:
                data = payload['body'].get('data')
                if data:
                    import base64
                    try:
                        text_content = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    except:
                        pass
        
        return text_content
    
    def check_gmail_for_new_code(self, account_id, email_filter):
        """Gmail'de yeni kod kontrol et - account + filter bazlı"""
        service = self.gmail_services.get(account_id)
        if not service:
            print(f"❌ Gmail servisi bağlı değil: {account_id}")
            return False
        
        try:
            filter_id = email_filter["id"]
            from_email = email_filter["from_email"]
            account_filter_key = f"{account_id}_{filter_id}"
            
            # Gmail query oluştur
            query = f"from:{from_email}"
            results = service.users().messages().list(userId='me', q=query, maxResults=1).execute()
            messages = results.get('messages', [])
            
            if not messages:
                print(f"📭 {from_email} mesajı bulunamadı ({account_id})")
                return False
            
            latest_msg = messages[0]
            latest_msg_id = latest_msg['id']
            
            # Bu account + filter için son mesajı kontrol et
            if self.last_message_ids.get(account_filter_key) == latest_msg_id:
                print(f"🔄 Aynı mesaj ({account_filter_key}): {latest_msg_id[:10]}...")
                return False
            
            # Mesaj detaylarını al
            msg_data = service.users().messages().get(userId='me', id=latest_msg_id).execute()
            
            headers = {h['name'].lower(): h['value'] for h in msg_data['payload']['headers']}
            subject = headers.get('subject', '')
            date_str = headers.get('date', '')
            
            # Mesaj tarihini kontrol et
            try:
                from email.utils import parsedate_to_datetime
                msg_date = parsedate_to_datetime(date_str)
                if msg_date <= self.system_start_time:
                    print(f"⏭️ Eski mesaj ({account_filter_key}): {subject[:30]}...")
                    self.last_message_ids[account_filter_key] = latest_msg_id
                    return False
            except:
                pass
            
            # Mesaj içeriğini al
            body_text = self.get_message_text(msg_data['payload'])
            
            # Kod tespiti
            detected_code = self.detect_code_from_content(body_text, email_filter)
            
            # Son mesaj ID'sini güncelle
            self.last_message_ids[account_filter_key] = latest_msg_id
            
            print(f"📨 YENİ MESAJ ({account_filter_key}): {subject[:40]}... - Kod: {detected_code or 'YOK'}")
            
            if detected_code:
                # Mevcut kodla aynı mı?
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                account_filter_id = f"{account_id}_{filter_id}"
                cursor.execute('SELECT current_code FROM system_status WHERE account_filter_id = ?', (account_filter_id,))
                current_code_result = cursor.fetchone()
                current_code = current_code_result[0] if current_code_result else None
                conn.close()
                
                if current_code == detected_code:
                    print(f"🔄 Aynı kod ({account_filter_key}): {detected_code}")
                    return False
                
                # Yeni farklı kod!
                self.set_current_code(account_id, filter_id, detected_code)
                return True
            
            return False
            
        except Exception as e:
            print(f"💥 Gmail kontrol hatası ({account_id}/{email_filter.get('id', 'unknown')}): {str(e)}")
            return False
    
    def set_current_code(self, account_id, filter_id, code):
        """Sistem kodunu güncelle - account + filter bazlı"""
        account_filter_id = f"{account_id}_{filter_id}"
        account_filter_key = f"{account_id}_{filter_id}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''UPDATE system_status 
                         SET current_code = ?, last_check = ?, last_message_id = ?
                         WHERE account_filter_id = ?''',
                      (code, datetime.now().isoformat(), 
                       self.last_message_ids.get(account_filter_key), account_filter_id))
        conn.commit()
        conn.close()
        
        print(f"🔥 YENİ KOD SİSTEME EKLENDİ ({account_filter_key}): {code}")
    
    def get_admin_stats(self):
        """Admin istatistikleri"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Genel stats
        cursor.execute('SELECT COUNT(*) FROM users WHERE user_key != "admin"')
        total_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM users WHERE has_code = 1 AND user_key != "admin"')
        users_with_code = cursor.fetchone()[0]
        
        # Account/filter bazlı stats
        cursor.execute('''SELECT account_id, filter_id, COUNT(*) FROM users 
                         WHERE user_key != "admin" 
                         GROUP BY account_id, filter_id''')
        users_by_account_filter = cursor.fetchall()
        
        # Tüm kullanıcıları listele
        cursor.execute('''SELECT user_key, account_id, filter_id, has_code, received_code, code_received_date, created_date
                         FROM users 
                         WHERE user_key != "admin" 
                         ORDER BY created_date DESC''')
        all_users = cursor.fetchall()
        
        # Account + filter durumları
        cursor.execute('SELECT account_filter_id, account_id, filter_id, current_code, last_check FROM system_status')
        filter_statuses = cursor.fetchall()
        
        conn.close()
        
        return {
            "total_users": total_users,
            "users_with_code": users_with_code,
            "users_waiting": total_users - users_with_code,
            "users_by_account_filter": [
                {
                    "account_id": row[0],
                    "filter_id": row[1],
                    "count": row[2]
                }
                for row in users_by_account_filter
            ],
            "scanning_active": self.scanning_active,
            "connected_accounts": len(self.gmail_services),
            "total_accounts": len(self.admin_config.get("gmail_accounts", [])),
            "gmail_accounts": self.admin_config.get("gmail_accounts", []),
            "email_filters": self.admin_config.get("email_filters", []),
            "filter_statuses": [
                {
                    "account_filter_id": status[0],
                    "account_id": status[1],
                    "filter_id": status[2],
                    "current_code": status[3],
                    "last_check": status[4]
                }
                for status in filter_statuses
            ],
            "all_users": [
                {
                    "key": user[0],
                    "account_id": user[1],
                    "filter_id": user[2],
                    "has_code": bool(user[3]),
                    "code": user[4],
                    "code_date": user[5],
                    "created_date": user[6]
                }
                for user in all_users
            ]
        }
    
    def start_scanning(self):
        """Gmail taramayı başlat - tüm aktif hesaplar ve filterler için"""
        if self.scanning_active:
            return {"error": "Tarama zaten aktif"}
        
        if not self.gmail_services:
            return {"error": "Gmail hesapları bağlı değil! Önce hesap kurulumu yapın."}
        
        active_filters = []
        for email_filter in self.admin_config.get("email_filters", []):
            if email_filter.get("active", True):
                account_id = email_filter.get("account_id")
                if account_id in self.gmail_services:
                    active_filters.append(email_filter)
        
        if not active_filters:
            return {"error": "Aktif ve bağlı email filter bulunamadı!"}
        
        self.scanning_active = True
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        
        print(f"🔄 Çoklu hesap Gmail taraması başlatıldı - {len(active_filters)} filter aktif")
        return {"success": True, "message": f"Çoklu hesap Gmail taraması başlatıldı ({len(active_filters)} filter)"}
    
    def stop_scanning(self):
        """Taramayı durdur"""
        if not self.scanning_active:
            return {"error": "Tarama zaten durmuş"}
        
        self.scanning_active = False
        if self.scan_thread:
            self.scan_thread.join(timeout=1)
        
        print("⏸️ Çoklu hesap Gmail taraması durduruldu")
        return {"success": True, "message": "Çoklu hesap Gmail taraması durduruldu"}
    
    def _scan_loop(self):
        """Gmail tarama döngüsü - tüm aktif hesaplar ve filterler için"""
        while self.scanning_active:
            try:
                active_filters = []
                for email_filter in self.admin_config.get("email_filters", []):
                    if email_filter.get("active", True):
                        account_id = email_filter.get("account_id")
                        if account_id in self.gmail_services:
                            active_filters.append((account_id, email_filter))
                
                for account_id, email_filter in active_filters:
                    if not self.scanning_active:
                        break
                    
                    account_name = "Bilinmeyen"
                    for acc in self.admin_config.get("gmail_accounts", []):
                        if acc["id"] == account_id:
                            account_name = acc["name"]
                            break
                    
                    print(f"🔍 Gmail taranıyor: {account_name} -> {email_filter['name']} ({email_filter['from_email']})")
                    found_new = self.check_gmail_for_new_code(account_id, email_filter)
                    if found_new:
                        print(f"🎉 Yeni farklı kod bulundu: {account_name} -> {email_filter['name']}")
                
                time.sleep(5)  # 5 saniye bekle
                
            except Exception as e:
                print(f"💥 Tarama döngüsü hatası: {str(e)}")
                time.sleep(5)
    
    def add_email_filter(self, filter_config):
        """Yeni email filter ekle"""
        # Unique ID oluştur
        filter_id = filter_config.get("id") or f"filter_{int(time.time())}"
        filter_config["id"] = filter_id
        
        # Account ID kontrolü
        account_id = filter_config.get("account_id")
        if not account_id:
            return {"error": "account_id gerekli"}
        
        # Account mevcut mu?
        account_exists = any(acc["id"] == account_id for acc in self.admin_config.get("gmail_accounts", []))
        if not account_exists:
            return {"error": f"Account bulunamadı: {account_id}"}
        
        # Filtrelere ekle
        self.admin_config.setdefault("email_filters", []).append(filter_config)
        self.save_admin_config()
        
        # DB'ye status ekle
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        account_filter_id = f"{account_id}_{filter_id}"
        cursor.execute('''INSERT OR IGNORE INTO system_status 
                         (account_filter_id, account_id, filter_id, current_code, last_message_id, last_check)
                         VALUES (?, ?, ?, NULL, NULL, ?)''', 
                      (account_filter_id, account_id, filter_id, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        print(f"➕ Yeni email filter eklendi: {filter_config['name']} ({filter_id}) -> {account_id}")
        return {"success": True, "filter_id": filter_id}
    
    def update_email_filter(self, filter_id, updates):
        """Email filter güncelle"""
        filters = self.admin_config.get("email_filters", [])
        for i, f in enumerate(filters):
            if f["id"] == filter_id:
                filters[i].update(updates)
                self.save_admin_config()
                print(f"🔄 Email filter güncellendi: {filter_id}")
                return True
        return False
    
    def delete_email_filter(self, filter_id):
        """Email filter sil"""
        filters = self.admin_config.get("email_filters", [])
        new_filters = [f for f in filters if f["id"] != filter_id]
        
        if len(new_filters) != len(filters):
            self.admin_config["email_filters"] = new_filters
            self.save_admin_config()
            
            # DB'den de sil
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM system_status WHERE filter_id = ?', (filter_id,))
            conn.commit()
            conn.close()
            
            print(f"🗑️ Email filter silindi: {filter_id}")
            return True
        return False

# Flask App
app = Flask(__name__)
CORS(app, supports_credentials=True)

system = MultiAccountSecureSystem()

@app.route('/api/health')
def health():
    return {
        "status": "ok", 
        "scanning": system.scanning_active,
        "connected_accounts": len(system.gmail_services),
        "total_accounts": len(system.admin_config.get("gmail_accounts", [])),
        "secure": True,
        "filters_count": len(system.admin_config.get("email_filters", []))
    }

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Güvenli admin girişi"""
    data = request.json or {}
    password = data.get('password', '').strip()
    
    print("🔐 Multi account admin login denemesi")
    
    if not system.verify_admin_password(password):
        print("❌ Yanlış admin şifresi")
        return {"success": False, "error": "Yanlış şifre"}, 401
    
    # JWT token oluştur
    token = system.generate_admin_token()
    
    response = make_response({
        "success": True, 
        "message": "Multi account admin girişi başarılı",
        "expires_in": "8 hours"
    })
    
    response.set_cookie(
        'admin_token',
        token,
        httponly=True,
        secure=False,
        samesite='Lax',
        max_age=8*60*60
    )
    
    print("✅ Multi account admin giriş başarılı")
    return response

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    response = make_response({"success": True, "message": "Çıkış başarılı"})
    response.set_cookie('admin_token', '', expires=0)
    return response

def require_admin_auth():
    """Admin yetki kontrolü"""
    token = request.cookies.get('admin_token')
    if not token:
        return False
    return system.verify_admin_token(token)

@app.route('/api/admin/change_password', methods=['POST'])
def change_admin_password():
    """Admin şifresi değiştir"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    data = request.json or {}
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    
    if not current_password or not new_password:
        return {"success": False, "error": "Mevcut ve yeni şifre gerekli"}, 400
    
    if not system.verify_admin_password(current_password):
        return {"success": False, "error": "Mevcut şifre yanlış"}, 401
    
    if len(new_password) < 6:
        return {"success": False, "error": "Yeni şifre en az 6 karakter olmalı"}, 400
    
    system.update_admin_password(new_password)
    return {"success": True, "message": "Admin şifresi başarıyla değiştirildi"}

# Gmail Accounts API
@app.route('/api/admin/gmail_accounts', methods=['GET'])
def get_gmail_accounts():
    """Gmail hesaplarını getir"""
    if not require_admin_auth():
        return {"error": "Yetkisiz erişim"}, 403
    
    accounts = system.admin_config.get("gmail_accounts", [])
    # Hesapların bağlı olup olmadığını ekle
    for account in accounts:
        account["connected"] = account["id"] in system.gmail_services
    
    return {"accounts": accounts}

@app.route('/api/admin/gmail_accounts', methods=['POST'])
def add_gmail_account():
    """Yeni Gmail hesabı ekle"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    data = request.json or {}
    
    required_fields = ["name", "email"]
    for field in required_fields:
        if not data.get(field):
            return {"success": False, "error": f"{field} alanı gerekli"}, 400
    
    account_config = {
        "name": data["name"],
        "email": data["email"],
        "credentials_file": data.get("credentials_file", "credentials.json"),
        "active": data.get("active", True)
    }
    
    account_id = system.add_gmail_account(account_config)
    return {"success": True, "message": "Gmail hesabı eklendi", "account_id": account_id}

@app.route('/api/admin/gmail_accounts/<account_id>', methods=['PUT'])
def update_gmail_account(account_id):
    """Gmail hesabını güncelle"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    data = request.json or {}
    success = system.update_gmail_account(account_id, data)
    
    if success:
        return {"success": True, "message": "Gmail hesabı güncellendi"}
    else:
        return {"success": False, "error": "Hesap bulunamadı"}, 404

@app.route('/api/admin/gmail_accounts/<account_id>', methods=['DELETE'])
def delete_gmail_account(account_id):
    """Gmail hesabını sil"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    success = system.delete_gmail_account(account_id)
    
    if success:
        return {"success": True, "message": "Gmail hesabı silindi"}
    else:
        return {"success": False, "error": "Hesap bulunamadı"}, 404

@app.route('/api/admin/gmail_accounts/<account_id>/connect', methods=['POST'])
def connect_gmail_account(account_id):
    """Belirli Gmail hesabını bağla"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    try:
        success = system.authenticate_gmail_account(account_id)
        if success:
            return {"success": True, "message": "Gmail hesabı bağlandı"}
        else:
            return {"success": False, "error": "Bağlantı başarısız"}, 400
    except Exception as e:
        return {"success": False, "error": str(e)}, 400

@app.route('/api/admin/connect_all_accounts', methods=['POST'])
def connect_all_accounts():
    """Tüm aktif Gmail hesaplarını bağla"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    try:
        success = system.authenticate_all_accounts()
        if success:
            return {"success": True, "message": "Gmail hesapları bağlandı"}
        else:
            return {"success": False, "error": "Hiçbir hesap bağlanamadı"}, 400
    except Exception as e:
        return {"success": False, "error": str(e)}, 400

# Email Filters API
@app.route('/api/admin/email_filters', methods=['GET'])
def get_email_filters():
    """Email filterlerini getir"""
    if not require_admin_auth():
        return {"error": "Yetkisiz erişim"}, 403
    
    return {"filters": system.admin_config.get("email_filters", [])}

@app.route('/api/admin/email_filters', methods=['POST'])
def add_email_filter():
    """Yeni email filter ekle"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    data = request.json or {}
    
    required_fields = ["name", "account_id", "from_email", "trigger_phrases", "code_patterns"]
    for field in required_fields:
        if not data.get(field):
            return {"success": False, "error": f"{field} alanı gerekli"}, 400
    
    filter_config = {
        "name": data["name"],
        "account_id": data["account_id"],
        "from_email": data["from_email"],
        "trigger_phrases": data["trigger_phrases"] if isinstance(data["trigger_phrases"], list) else [data["trigger_phrases"]],
        "code_patterns": data["code_patterns"] if isinstance(data["code_patterns"], list) else [data["code_patterns"]],
        "active": data.get("active", True)
    }
    
    result = system.add_email_filter(filter_config)
    if result.get("success"):
        return {"success": True, "message": "Email filter eklendi", "filter_id": result["filter_id"]}
    else:
        return {"success": False, "error": result.get("error", "Filter eklenemedi")}, 400

@app.route('/api/admin/email_filters/<filter_id>', methods=['PUT'])
def update_email_filter(filter_id):
    """Email filter güncelle"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    data = request.json or {}
    success = system.update_email_filter(filter_id, data)
    
    if success:
        return {"success": True, "message": "Email filter güncellendi"}
    else:
        return {"success": False, "error": "Filter bulunamadı"}, 404

@app.route('/api/admin/email_filters/<filter_id>', methods=['DELETE'])
def delete_email_filter(filter_id):
    """Email filter sil"""
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    success = system.delete_email_filter(filter_id)
    
    if success:
        return {"success": True, "message": "Email filter silindi"}
    else:
        return {"success": False, "error": "Filter bulunamadı"}, 404

@app.route('/api/admin/create_key', methods=['POST'])
def create_key():
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    data = request.json or {}
    account_id = data.get('account_id')
    filter_id = data.get('filter_id')
    
    if not account_id or not filter_id:
        return {"success": False, "error": "account_id ve filter_id gerekli"}, 400
    
    new_key = system.create_user_key(account_id, filter_id)
    return {"success": True, "user_key": new_key, "account_id": account_id, "filter_id": filter_id, "message": f"Anahtar oluşturuldu: {new_key}"}

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.json or {}
    user_key = str(data.get('key', '')).lower().strip()
    
    if not user_key:
        return {"error": "Kullanıcı anahtarı gerekli"}, 400
    
    user = system.get_user(user_key)
    if not user:
        return {"error": "Geçersiz kullanıcı anahtarı"}, 401
    
    user_account_id = user[1]  # account_id
    user_filter_id = user[2]   # filter_id
    
    # Gmail hesabının email adresini bul
    account_email = "Bilinmeyen"
    for account in system.admin_config.get("gmail_accounts", []):
        if account["id"] == user_account_id:
            account_email = account["email"]
            break
    
    # Email filter'ın adını bul
    filter_name = "Bilinmeyen Filter"
    for email_filter in system.admin_config.get("email_filters", []):
        if email_filter["id"] == user_filter_id:
            filter_name = email_filter["name"]
            break
    
    return {
        "success": True,
        "user_key": user_key,
        "account_id": user_account_id,
        "filter_id": user_filter_id,
        "account_email": account_email,
        "filter_name": filter_name,
        "has_received_code": bool(user[3]),
        "last_code_received": user[4],
        "created_date": user[6]
    }

@app.route('/api/get_my_code', methods=['POST'])
def get_code():
    data = request.json or {}
    user_key = str(data.get('key', '')).lower().strip()
    
    if not user_key:
        return {"error": "Kullanıcı anahtarı gerekli"}, 400
    
    result = system.assign_code_to_user(user_key)
    return result

@app.route('/api/admin/start_scanning', methods=['POST'])
def start_scan():
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    result = system.start_scanning()
    return result

@app.route('/api/admin/stop_scanning', methods=['POST'])
def stop_scan():
    if not require_admin_auth():
        return {"success": False, "error": "Yetkisiz erişim"}, 403
    
    result = system.stop_scanning()
    return result

@app.route('/api/admin/stats', methods=['GET', 'POST'])
def admin_stats():
    if not require_admin_auth():
        return {"error": "Yetkisiz erişim"}, 403
    
    return system.get_admin_stats()

@app.route('/api/admin/check_auth', methods=['GET'])
def check_admin_auth():
    is_authenticated = require_admin_auth()
    return {
        "authenticated": is_authenticated,
        "message": "Admin oturumu aktif" if is_authenticated else "Admin girişi gerekli"
    }

@app.route('/setup_gmail', methods=['GET', 'POST'])
def setup_gmail():
    """Gmail kurulum sayfası"""
    if request.method == 'POST':
        account_id = request.form.get('account_id', 'account_1')
        try:
            system.authenticate_gmail_account(account_id)
            return f"✅ Gmail hesabı başarıyla bağlandı: {account_id}"
        except Exception as e:
            return f"❌ Gmail bağlantı hatası: {str(e)}"
    
    # Hesap kartları HTML oluştur
    accounts = system.admin_config.get("gmail_accounts", [])
    connected_count = len(system.gmail_services)
    
    account_cards = []
    for acc in accounts:
        status_text = "🟢 Bağlı" if acc['id'] in system.gmail_services else "🔴 Bağlı Değil"
        card_html = f'''
        <div class="account">
            <strong>{acc['name']}</strong> ({acc['email']}) - {acc['id']}<br>
            <small>Credentials: {acc.get('credentials_file', 'credentials.json')}</small><br>
            <small>Status: {status_text}</small><br>
            <form method="post" style="display: inline;">
                <input type="hidden" name="account_id" value="{acc['id']}">
                <button type="submit" class="btn">🔗 Bu Hesabı Bağla</button>
            </form>
        </div>
        '''
        account_cards.append(card_html)
    
    accounts_html = "".join(account_cards)
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Multi Account Gmail API Setup</title>
        <style>
            body {{ font-family: Arial; margin: 50px; background: #f5f5f5; }}
            .container {{ background: white; padding: 30px; border-radius: 10px; max-width: 800px; }}
            .btn {{ background: #3b82f6; color: white; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; margin: 5px; }}
            .status {{ padding: 15px; border-radius: 6px; margin: 20px 0; }}
            .success {{ background: #d1ecf1; border-left: 4px solid #10b981; }}
            .warning {{ background: #fff3cd; border-left: 4px solid #f59e0b; }}
            .secure {{ background: #e0f2fe; border-left: 4px solid #0288d1; }}
            .multi {{ background: #f3e5f5; border-left: 4px solid #9c27b0; }}
            .account {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📧 Multi Account Gmail API Setup</h2>
            
            <div class="status multi">
                <strong>🚀 ÇOK HESAPLI SİSTEM ÖZELLİKLERİ:</strong>
                <ul>
                    <li>✅ Çoklu Gmail hesabı desteği</li>
                    <li>✅ Hesap bazlı email filtreleri</li>
                    <li>✅ Hesap + filter bazlı key oluşturma</li>
                    <li>✅ Her hesap için ayrı credentials</li>
                    <li>✅ Dinamik hesap ekleme/silme</li>
                </ul>
            </div>
            
            <div class="status {'success' if connected_count > 0 else 'warning'}">
                <strong>Gmail Durumu:</strong> {connected_count}/{len(accounts)} hesap bağlı<br>
                <strong>Config:</strong> {system.config_file}
            </div>
            
            <h3>📧 Gmail Hesapları:</h3>
            {accounts_html}
            
            <div class="status success">
                <h3>🎯 Sistem Özellikleri:</h3>
                <ul>
                    <li>✅ Çoklu Gmail hesabı tarama</li>
                    <li>✅ Hesap bazlı filter sistemi</li>
                    <li>✅ Account + filter kombinasyonu key'leri</li>
                    <li>✅ Farklı credentials dosyaları</li>
                    <li>✅ Admin panelden hesap yönetimi</li>
                </ul>
            </div>
            
            <div class="status secure">
                <h3>📁 Config Yapısı:</h3>
                <p><code>multi_account_config.json</code>:</p>
                <ul>
                    <li><strong>gmail_accounts:</strong> Hesap listesi</li>
                    <li><strong>email_filters:</strong> Her filter bir account'a bağlı</li>
                    <li><strong>credentials:</strong> Her hesap için ayrı credentials.json</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("🚀 Multi Account Secure System - Çoklu Gmail + Filter")
    print("📧 ÖZELLİKLER:")
    print(f"  ✅ Gmail hesapları: {len(system.admin_config.get('gmail_accounts', []))} adet")
    print(f"  ✅ Email filtreleri: {len(system.admin_config.get('email_filters', []))} adet")
    print("  ✅ Çoklu hesap desteği")
    print("  ✅ Hesap + filter bazlı key oluşturma")
    print("  ✅ Dinamik hesap yönetimi")
    print("🔒 GÜVENLİK:")
    print(f"  ✅ Admin şifresi: {system.admin_config.get('admin_password', 'Zort123.')}")
    print("  ✅ JWT + PBKDF2 + HttpOnly cookies")
    print("🔧 Port: 5000")
    print("📧 Gmail kurulum: http://localhost:5000/setup_gmail")
    
    app.run(debug=True, host='0.0.0.0', port=5000)