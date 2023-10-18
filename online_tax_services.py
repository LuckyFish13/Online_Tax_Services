''' 
    Online_Tax_Services - HMRC VAT MTD Python wrapper
    Copyright (C) 2023 Ronin Customs Ltd.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import os
import sys
import csv
import json
import uuid
import pyotp
import ifcfg
import shutil
import sqlite3
import binascii
import argparse
import requests
import datetime
import pyautogui
import webbrowser
import http.server
import socketserver

from hashlib import sha256
from getpass import getpass

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from requests_oauthlib import OAuth2Session
from urllib.parse import quote, urlparse, parse_qs
from oauthlib.oauth2 import BackendApplicationClient

global AUTH_CODE
global AUTH_STATE

AUTH_CODE = ''
AUTH_STATE = ''

class RedirectParser(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):

        global AUTH_CODE
        global AUTH_STATE

        self.send_response(200)

        self.send_header("Content-type", "text/html")
        self.end_headers()

        query_components = parse_qs(urlparse(self.path).query)

        if 'code' not in query_components or 'state' not in query_components:
            return 1

        AUTH_CODE = query_components["code"][0]
        AUTH_STATE = query_components["state"][0]

        d = {"success": True}
        message = json.dumps(d)
        self.wfile.write(bytes(message, "utf8"))

        return 0

class OnlineTaxServices():

    run_mode = ''

    config_file = ''
    config = {}

    database_file = ''
    key_file = ''

    pwd = b''
    key = b''
    dec_iv = b''
    enc_iv = b''

    session = None
    response = None

    headers = {}

    client_index = None
    active_client = ''
    access_token = ''

    def __init__(self) -> None:

        self.run_mode = 'SHELL'

        self.config_file = './app.data'
        self.database_file = './users.db'
        self.key_file = './key.key'

        self.GetUserArgs()

    def GetUserArgs(self):

        if(len(sys.argv) > 2):
            print('Invalid usage! Exiting...')
            sys.exit(1)

        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--install", action='store_true', help=f"Install configuration")
        parser.add_argument("-p", "--password", action='store_true', help=f"Change user password")
        parser.add_argument("-g", "--generate", action='store_true', help=f"Generate new authenticator QR code")
        args = parser.parse_args()
        
        if args.install == True:

            if args.password == True or args.generate == True:
                print('Invalid usage! Exiting...')
                sys.exit(1)

            if os.geteuid() != 0:
                print('Run installer as root! Exiting...')
                sys.exit(1)
            
            if os.path.exists(self.key_file) == True:
                print('Key file already exists! Exiting...')
                sys.exit(1)
            
            if os.path.exists(self.database_file) == True:
                print('Database file already exists! Exiting...')
                sys.exit(1)

            if os.path.exists(self.config_file) == True:
                print('Config file already exists! Exiting...')
                sys.exit(1)
            
            self.run_mode = 'INSTALL'
            return {}

        if os.geteuid() == 0:
            print('Do not run interactive shell, password changer, or generator as root! Exiting...')
            sys.exit(1)

        if os.path.exists(self.key_file) == False:
            print('Key file does not exist! Exiting...')
            sys.exit(1)
        name, ext =  os.path.splitext(self.key_file)
        if ext != '.key':
            print("Invalid key file! Exiting...")
            sys.exit(1)

        if os.path.exists(self.database_file) == False:
            print('Database file does not exist! Exiting...')
            sys.exit(1)
        name, ext =  os.path.splitext(self.database_file)
        if ext != '.db':
            print("Invalid database file! Exiting...")
            sys.exit(1)

        if os.path.exists(self.config_file) == False:
            print('Config file does not exist! Exiting...')
            sys.exit(1)
        name, ext =  os.path.splitext(self.config_file)
        if ext != '.data':
            print("Invalid config file! Exiting...")
            sys.exit(1)

        if args.password == True:
            if args.generate == True:
                print('Invalid usage! Exiting...')
                sys.exit(1)
            self.run_mode = 'PASSWORD'

        if args.generate == True:
            self.run_mode = 'GENERATE'

        self.config = self.CheckPassword()

        if self.config == {} or self.config == None:
            print("incorrect password! exiting...")
            sys.exit(1)

        ic = input(f"Enter OTP: ")
        if self.CheckOtp(ic) != 0:
            print("Invalid OTP! exiting...")
            sys.exit(1)
    
    def SaveConfig(self) -> None:
        self.CreateBackupFiles()
        self.enc_iv = self.GenerateIv()
        self.UpdateSavedIv()
        self.WriteKeyFile()
        self.WriteConfigFile()
        self.dec_iv = self.enc_iv

    def CreateBackupFiles(self) -> int:
        try:
            d = self.database_file + '.bk'
            k = self.key_file + '.bk'
            c = self.config_file + '.bk'
            shutil.copyfile(self.database_file, d)
            shutil.copyfile(self.key_file, k)
            shutil.copyfile(self.config_file, c)
            os.system(f"chmod 644 {d}")
            os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {d}")
            os.system(f"chmod 644 {k}")
            os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {k}")
            os.system(f"chmod 644 {c}")
            os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {c}")
            return 0
        except Exception:
            return 1

    def EncodeString(self, string) -> str:
        return quote(string, safe='-=.')
    
    def CalculateHash(self, string: str) -> str:
        return sha256(string.encode('utf-8')).hexdigest()

    def EncryptBytes(self, key, iv, clear) -> bytes:
        ctr = Counter.new(AES.block_size * 8, initial_value=int(iv, 16))
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        return aes.encrypt(clear)

    def DecryptBytes(self, key, iv, cipher) -> str:
        ctr = Counter.new(AES.block_size * 8, initial_value=int(iv, 16))
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        return aes.decrypt(cipher)

    def GetClientIndex(self, string):
        for client in self.config['DATABASE_INFO']:
            for key, value in client.items():
                if key == 'CLIENT_ID' and value == string:
                    return self.config['DATABASE_INFO'].index(client)
        return None
    
    def GetReturnIndex(self, string):
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return None
        for v_return in self.config['DATABASE_INFO'][self.client_index]['RETURNS']:
            for key, value in v_return.items():
                if key == 'PERIOD_KEY' and value == string:
                    return self.config['DATABASE_INFO'][self.client_index]['RETURNS'].index(v_return)
        return None

    def CheckOtp(self, otp) -> int:
        if otp == pyotp.TOTP(self.config['USER_INFO']['TOTP_SECRET']).now():
            
            ip_info = []
            mac_info = []
            
            for name, interface in ifcfg.interfaces().items():
                if interface['inet'] is not None:
                    ip_info.append(interface['inet'])
                if interface['ether'] is not None:
                    mac_info.append(interface['ether'])

            if len(ip_info) < 1 or len(mac_info) < 1:
                print('Check connection and try again! Exiting...')
                sys.exit(1)
            
            ip_str = ip_info[0]
            mac_str = self.EncodeString(mac_info[0])
            if len(ip_info) > 1:
                for ip in ip_info:
                    if ip_info.index(ip) != 0:
                        ip_str += ',' + ip
            if len(mac_info) > 1:
                for mac in mac_info:
                    if mac_info.index(mac) != 0:
                        mac_str += ',' + self.EncodeString(mac)

            date_time = datetime.datetime.now(datetime.timezone(datetime.timedelta()))
            zone = datetime.datetime.now(datetime.timezone(datetime.timedelta())).astimezone().tzinfo

            self.config['LOGIN_INFO'].update({"IP": str(ip_str)})
            self.config['LOGIN_INFO'].update({"TIME": f"{date_time.date()}T{date_time.strftime('%X')}.{date_time.microsecond // 1000:03d}Z"})
            self.config['LOGIN_INFO'].update({"TZ": str(zone)})
            self.config['LOGIN_INFO'].update({"MAC": str(mac_str)})
            self.config['LOGIN_INFO'].update({"MFA": f"type={self.config['USER_INFO']['OTP_TYPE']}&timestamp={self.EncodeString(self.config['LOGIN_INFO']['TIME'])}&unique-reference={self.EncodeString(self.config['USER_INFO']['OTP_REFERENCE'])}"})

            term = os.get_terminal_size()
            self.config['AGENT_INFO']['SCREEN'].update({"W_WIDTH": ((term.columns * 16) + 30)})
            self.config['AGENT_INFO']['SCREEN'].update({"W_HEIGHT": ((term.lines * 35) + 31)})

            self.SaveConfig()

            return 0
        else:
            return -1

    def Install(self) -> int:

        if self.config != {}:
            print("Broken config! Exiting...")
            sys.exit(1)
        
        if os.geteuid() != 0:
            print('Run installer as root! Exiting...')
            sys.exit(1)

        c_ver = {}
        c_app = {}
        c_use = {}
        c_dev = {}
        c_scr = {}
        c_agn = {}

        #version control!
        c_ver.update({"APP_NAME": "Ronin_Customs_Internal_VAT"})
        c_ver.update({"APP_VERSION": "0.0.6"})

        #app info
        id = str(input("Enter HMRC Client ID: "))
        sec = str(input("Enter HMRC Client Secret: "))
        try:
            uri = int(input("Enter URI port: "))
        except Exception:
            print("Port must be int! Exiting...")
            sys.exit(1)
        if uri < 1024:
            print("Port must be > 1023! Exiting...")
            sys.exit(1)
        if uri > 65535:
            print("Port must be < 65536! Exiting...")
            sys.exit(1)
        c_app.update({"BASE_URL": "https://test-api.service.hmrc.gov.uk/"})
        c_app.update({"CLIENT_ID": f"{id}"})
        c_app.update({"CLIENT_SECRET": f"{sec}"})
        c_app.update({"URI_PORT": uri})

        #user info
        user = str(input("Enter UserName: "))
        c_use.update({"USER_NAME": f"{user}"})
        c_use.update({"OTP_TYPE": "TOTP"})

        #device info
        domn = str(input("Enter Domain/Group: "))
        c_dev.update({"DOMAIN": f"{domn}"})
        c_dev.update({"CONNECTION_METHOD": "DESKTOP_APP_DIRECT"})
        c_dev.update({"DEVICE_ID": f"{str(uuid.uuid4())}"})
        c_dev.update({"LICENSE": self.CalculateHash(c_dev['DEVICE_ID'])})

        #screen info
        import tkinter
        root = tkinter.Tk()
        c_scr.update({"WIDTH": f"{root.winfo_screenwidth()}"})
        c_scr.update({"HEIGHT": f"{root.winfo_screenheight()}"})
        root.destroy
        import subprocess
        out = subprocess.check_output(['xwininfo', '-root']).decode('utf-8')
        start = out.find('Depth')
        depth = int(out[start+7:start+9])
        if depth != 24 or depth != 32:
            depth = 24
        out = subprocess.check_output(['xrdb', '-query']).decode('utf-8')
        start = out.find('Xft.dpi')
        scale = int(round(float(out[start+9:start+12])/100.0))
        if scale < 1:
            scale = 1
        c_scr.update({"SCALING": scale})
        c_scr.update({"COLOUR": depth})
        term = os.get_terminal_size()
        c_scr.update({"W_WIDTH": ((term.columns * 16) + 30)})
        c_scr.update({"W_HEIGHT": ((term.lines * 35) + 31)})
        #agent info
        import platform
        from dmidecode.decode import DMIDecode
        dmi = DMIDecode()
        c_agn.update({"SYSTEM": platform.system()})
        c_agn.update({"RELEASE": platform.release()})
        c_agn.update({"MANUFACTURER": dmi.manufacturer()})
        c_agn.update({"PRODUCT": dmi.model()})
        c_agn.update({"SCREEN": c_scr})

        self.config.update({"VERSION_INFO": c_ver})
        self.config.update({"APP_CONFIG": c_app})
        self.config.update({"USER_INFO": c_use})
        self.config.update({"DEVICE_INFO": c_dev})
        self.config.update({"AGENT_INFO": c_agn})
        self.config.update({"LOGIN_INFO": {}})
        self.config.update({"DATABASE_INFO": []})

        salt = get_random_bytes(16)
        p_key = PBKDF2(bytes(str(getpass('Create Password: ')).encode('utf-8')), salt, 32, count=1000000, hmac_hash_module=SHA512)
        pc_key = PBKDF2(bytes(str(getpass('Confirm Password: ')).encode('utf-8')), salt, 32, count=1000000, hmac_hash_module=SHA512)

        if(p_key != pc_key):
            print("passwords do not match! exiting...")
            sys.exit(1)

        self.pwd = pc_key

        self.key = get_random_bytes(32)

        self.enc_iv = self.GenerateIv()

        conn = sqlite3.connect(self.database_file)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE users (name TEXT PRIMARY KEY,salt BLOB, iv BLOB);''')
        cur.execute('''INSERT INTO users(name,salt,iv) VALUES(?,?,?)''', (self.config['USER_INFO']['USER_NAME'], salt, self.enc_iv))
        conn.commit()
        conn.close()

        self.WriteKeyFile()

        self.WriteConfigFile()

        os.system(f"chmod 644 {self.database_file}")
        os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {self.database_file}")
        os.system(f"chmod 644 {self.key_file}")
        os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {self.key_file}")
        os.system(f"chmod 644 {self.config_file}")
        os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {self.config_file}")

        if self.GenerateSecret() != 0:
            print("TOTP generator failed! Exiting...")
            sys.exit(1)

        return 0

    def ReadKeyFile(self) -> bytes:
        try:
            with open(self.key_file, 'rb') as key_file:
                return self.DecryptBytes(self.pwd, self.dec_iv, key_file.read())
        except Exception:
            return b''

    def WriteKeyFile(self) -> int:
        with open(self.key_file, 'wb') as key_file:
            key_file.write(self.EncryptBytes(self.pwd, self.enc_iv, self.key))
        return 0

    def ReadConfigFile(self) -> dict:
        try:
            with open(self.config_file, 'rb') as cfg_file:
                return json.loads(self.DecryptBytes(self.key, self.dec_iv, cfg_file.read()).decode('utf-8'))
        except Exception:
            return {}

    def WriteConfigFile(self) -> int:
        with open(self.config_file, 'wb') as cfg_file:
            cfg_file.write(self.EncryptBytes(self.key, self.enc_iv, bytes(json.dumps(self.config).encode('utf-8'))))
        return 0

    def CheckPassword(self) -> dict:
        salt = self.GetSavedSalt()
        self.pwd = PBKDF2(bytes(str(getpass('Enter Password: ')).encode('utf-8')), salt, 32, count=1000000, hmac_hash_module=SHA512)
        self.dec_iv = self.GetSavedIV()
        self.key = self.ReadKeyFile()
        return self.ReadConfigFile()

    def ChangePassword(self) -> int:
        salt = self.GetSavedSalt()
        op = PBKDF2(bytes(str(getpass('Enter Old Password: ')).encode('utf-8')), salt, 32, count=1000000, hmac_hash_module=SHA512)
        self.pwd = op
        if self.key != self.ReadKeyFile():
            print("incorrect password! exiting...")
            sys.exit(1)
        np = PBKDF2(bytes(str(getpass('Create New Password: ')).encode('utf-8')), salt, 32, count=1000000, hmac_hash_module=SHA512)
        npc = PBKDF2(bytes(str(getpass('Confirm New Password: ')).encode('utf-8')), salt, 32, count=1000000, hmac_hash_module=SHA512)
        if(np != npc):
            print("passwords do not match! exiting...")
            sys.exit(1)
        self.pwd = npc
        self.WriteKeyFile()
        return 0
    
    def ReadDbInfo(self, i) -> bytes:
        ret = b''
        conn = sqlite3.connect(self.database_file)
        cur = conn.cursor()
        cur.execute('''SELECT * FROM users''')
        for x in cur.fetchall():
            ret = x[i]
            break
        conn.close()
        return ret

    def GetSavedSalt(self) -> bytes:
        return self.ReadDbInfo(1)

    def GetSavedIV(self) -> bytes:
        return self.ReadDbInfo(2)

    def GenerateIv(self) -> int:
        return binascii.hexlify(Random.new().read(AES.block_size))

    def UpdateSavedIv(self) -> int:
        try:
            conn = sqlite3.connect(self.database_file)
            cur = conn.cursor()
            cur.execute('''UPDATE users SET iv = ? WHERE name = ?''', (self.enc_iv, self.config['USER_INFO']['USER_NAME']))
            conn.commit()
            conn.close()
            return 0
        except Exception:
            return 1

    def GenerateSecret(self) -> int:
        import qrcode
        self.config['USER_INFO'].update({"TOTP_SECRET": pyotp.random_base32()})
        self.config['USER_INFO'].update({"OTP_REFERENCE": self.CalculateHash(self.config['USER_INFO']['TOTP_SECRET'])})
        self.SaveConfig()
        auth = pyotp.TOTP(self.config['USER_INFO']['TOTP_SECRET']).provisioning_uri(name=self.config['USER_INFO']['USER_NAME'], issuer_name=self.config['VERSION_INFO']['APP_NAME'])
        file_name = './qrcode.png'
        qrcode.make(auth).save(file_name)
        os.system(f"chmod 644 {file_name}")
        os.system(f"chown {self.config['USER_INFO']['USER_NAME']}:{self.config['DEVICE_INFO']['DOMAIN']} {file_name}")
        return 0

    def PopulateHeaders(self):

        self.headers = {}
        self.headers.update({"Accept": "application/vnd.hmrc.1.0+json"})
        self.headers.update({"Gov-Client-Connection-Method": self.config['DEVICE_INFO']['CONNECTION_METHOD']})
        self.headers.update({"Gov-Client-Device-ID": self.config['DEVICE_INFO']['DEVICE_ID']})
        self.headers.update({"Gov-Client-Local-IPs": self.config['LOGIN_INFO']['IP']})
        self.headers.update({"Gov-Client-Local-IPs-Timestamp": self.config['LOGIN_INFO']['TIME']})
        self.headers.update({"Gov-Client-MAC-Addresses": self.config['LOGIN_INFO']['MAC']})
        self.headers.update({"Gov-Client-Multi-Factor": self.config['LOGIN_INFO']['MFA']})
        self.headers.update({"Gov-Client-Screens": f"width={self.config['AGENT_INFO']['SCREEN']['WIDTH']}&height={self.config['AGENT_INFO']['SCREEN']['HEIGHT']}&scaling-factor={self.config['AGENT_INFO']['SCREEN']['SCALING']}&colour-depth={self.config['AGENT_INFO']['SCREEN']['COLOUR']}"})
        if(self.config['LOGIN_INFO']['TZ'] == 'BST'):
            self.headers.update({"Gov-Client-Timezone": "UTC+01:00"})
        else:
            self.headers.update({"Gov-Client-Timezone": "UTC+00:00"})
        self.headers.update({"Gov-Client-User-Agent": f"os-family={self.EncodeString(self.config['AGENT_INFO']['SYSTEM'])}&os-version={self.EncodeString(self.config['AGENT_INFO']['RELEASE'])}&device-manufacturer={self.EncodeString(self.config['AGENT_INFO']['MANUFACTURER'])}&device-model={self.EncodeString(self.config['AGENT_INFO']['PRODUCT'])}"})
        self.headers.update({"Gov-Client-User-IDs": f"os={self.EncodeString(self.config['DEVICE_INFO']['DOMAIN'])}&my-application={self.EncodeString(self.config['USER_INFO']['USER_NAME'])}"})
        self.headers.update({"Gov-Client-Window-Size": f"width={self.config['AGENT_INFO']['SCREEN']['W_WIDTH']}&height={self.config['AGENT_INFO']['SCREEN']['W_HEIGHT']}"})
        self.headers.update({"Gov-Vendor-License-IDs": f"my-licensed-application={self.config['DEVICE_INFO']['LICENSE']}"})
        self.headers.update({"Gov-Vendor-Product-Name": f"{self.config['VERSION_INFO']['APP_NAME']}"})
        self.headers.update({"Gov-Vendor-Version": f"my-application={self.config['VERSION_INFO']['APP_VERSION']}"})
        return self.headers

    def RequestNewRefreshToken(self) -> str:
        #sanity check
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return ''
        global AUTH_CODE
        global AUTH_STATE
        #get access key
        self.session = OAuth2Session(client=BackendApplicationClient(client_id=self.config['APP_CONFIG']['CLIENT_ID']), scope=["default"])
        self.access_token = self.session.fetch_token(token_url=f"{self.config['APP_CONFIG']['BASE_URL']}oauth/token", client_id=self.config['APP_CONFIG']['CLIENT_ID'], client_secret=self.config['APP_CONFIG']['CLIENT_SECRET'], include_client_id=True)['access_token']
        #get refresh token
        self.session = OAuth2Session(self.config['APP_CONFIG']['CLIENT_ID'], scope=["read:vat", "write:vat"], redirect_uri=f"http://localhost:{self.config['APP_CONFIG']['URI_PORT']}/")
        auth_url, state = self.session.authorization_url(f"{self.config['APP_CONFIG']['BASE_URL']}oauth/authorize")
        #open url in default browser
        print("Redirecting to web browser...")
        webbrowser.open(auth_url, new=2, autoraise=True)
        handler = RedirectParser
        try:
            with socketserver.TCPServer(("", self.config['APP_CONFIG']['URI_PORT']), handler) as httpd:
                httpd.handle_request()
                httpd.server_close()
        except Exception as e:
            print("Too many frequent requests! exiting...")
            sys.exit(1)
        pyautogui.hotkey('ctrl','w')
        #catch redirect
        redirect_response = f"https://localhost:{self.config['APP_CONFIG']['URI_PORT']}/?code={AUTH_CODE}&state={AUTH_STATE}"
        #get token
        return self.session.fetch_token(f"{self.config['APP_CONFIG']['BASE_URL']}oauth/token", client_secret=self.config['APP_CONFIG']['CLIENT_SECRET'], include_client_id=True, authorization_response=redirect_response)['refresh_token']

    def ExchangeRefreshToken(self, token) -> str:
        #sanity check
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return ''
        self.session = OAuth2Session(self.config['APP_CONFIG']['CLIENT_ID'], scope=["read:vat", "write:vat"])
        self.response = self.session.refresh_token(f"{self.config['APP_CONFIG']['BASE_URL']}oauth/token", client_id=self.config['APP_CONFIG']['CLIENT_ID'], client_secret=self.config['APP_CONFIG']['CLIENT_SECRET'], include_client_id=True, refresh_token=token)
        self.access_token = self.response['access_token']
        return self.response['refresh_token']

    def SelectClient(self, id) -> int:
        if id == None:
            self.active_client = ''
            self.client_index = None
            return 0
        index = self. GetClientIndex(id)
        if index == None:
            print("Client does not exist!")
            return 1
        self.client_index = index
        self.active_client = self.config['DATABASE_INFO'][index]['CLIENT_ID']
        #get access token
        try:
            self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'] = self.ExchangeRefreshToken(self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'])
            self.SaveConfig()
            return 0
        except Exception:
            self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'] = self.RequestNewRefreshToken()
            self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'] = self.ExchangeRefreshToken(self.config['DATABASE_INFO'][index]['REFRESH_TOKEN'])
            self.SaveConfig()
            return 0

    def VerifyVatNumber(self, no) -> int:
        try:
            vat_no = int(no)
            if vat_no < 0 or vat_no > 999999999:
                print('Invalid VAT number!')
                return -1
        except Exception:
            print('Invalid VAT number!')
            return -1
        return vat_no

    def CheckVatNumber(self, vat_no):

        self.PopulateHeaders()
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/check-vat-number/lookup/{vat_no}", headers=self.headers)
        return self.response.json()

    def PrintObligations(self, obs, quiet):
        try:
            l = len(obs['obligations'])
            if quiet == False and l > 0:
                print(f"Period Key\tPeriod Start\tPeriod End\tStatus\t\tPayment Date")
                for ob in obs['obligations']:
                    if ob['status'] == 'O':
                        stat = f"Open\t\t{ob['due']}"
                    else:
                        stat = f"Fulfilled\t{ob['received']}"
                    print(f"{ob['periodKey']}\t\t{ob['start']}\t{ob['end']}\t{stat}")
            return l
        except Exception:
            return -1

    def RetrieveObligationsByStatus(self, status, quiet=False) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        if status == 'O' or status == 'F':
            self.PopulateHeaders()
            self.headers.update({"Authorization": f"Bearer {self.access_token}"})
            self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/obligations?status={status}", headers=self.headers)
            obs = self.response.json()
            n = self.PrintObligations(obs, quiet)
            if n < 0:
                return -1
            return n
        else:
            return -1

    def RetrieveObligationsByDate(self, start_date, end_date, quiet=False) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/obligations?from={start_date}&to={end_date}", headers=self.headers)
        obs = self.response.json()
        return self.PrintObligations(obs, quiet)

    def RetrieveReturn(self, period_key, save_csv=False) -> int:
        if period_key == '':
            print("Not found!")
            return -1
        for ret in self.config['DATABASE_INFO'][self.client_index]['RETURNS']:
            if ret['PERIOD_KEY'] == period_key:
                try:
                    if save_csv == True:
                        self.SaveReturn(ret['RETURN'])
                    else:
                        self.DisplayReturn(ret['RETURN'])
                    return 0
                except Exception:
                    pass
        try:
            if self.ViewReturn(period_key) < 0:
                print("Not found!")
                return -1
            i = self.GetReturnIndex(period_key)
            if i == None:
                return_info = {}
                return_info.update({"PERIOD_KEY": period_key})
                return_info.update({"RETURN": self.response.json()})
                self.config['DATABASE_INFO'][self.client_index]['RETURNS'].append(return_info)
            else:
                self.config['DATABASE_INFO'][self.client_index]['RETURNS'][i].update({"RETURN": self.response.json()})
            self.SaveConfig()
            if save_csv == True:
                self.SaveReturn(self.response.json())
            else:
                self.DisplayReturn(self.response.json())
            return 0
        except Exception:
            print("Not found!")
            return -1

    def ViewReturn(self, period_key) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/returns/{period_key}", headers=self.headers)
        try:
            if self.response.status_code != 200:
                return -1
        except Exception:
            return -1
        return 0
    
    def DisplayReturn(self, vat_return) -> int:
        print(f"PeriodKey: {vat_return['periodKey']}")
        print(f"1. VAT due on sales: {vat_return['vatDueSales']}")
        print(f"2. VAT due on acquisitions: {vat_return['vatDueAcquisitions']}")
        print(f"3. Total VAT due: {vat_return['totalVatDue']}")
        print(f"4. Total VAT reclaimed: {vat_return['vatReclaimedCurrPeriod']}")
        print(f"5. Net VAT due: {vat_return['netVatDue']}")
        print(f"6. Total value of sales: {vat_return['totalValueSalesExVAT']}")
        print(f"7. Total value of purchases: {vat_return['totalValuePurchasesExVAT']}")
        print(f"8. Total value of supplies: {vat_return['totalValueGoodsSuppliedExVAT']}")
        print(f"9. Total value of acquisitions: {vat_return['totalAcquisitionsExVAT']}")
        return 0
    
    def SaveReturn(self, vat_return) -> int:
        if vat_return == {}:
            print("Not found!")
            return -1
        try:
            date_time = datetime.datetime.now(datetime.timezone(datetime.timedelta()))
            with open(f"{self.active_client}_{vat_return['periodKey']}_{date_time.isoformat()}.csv", 'w') as f:
                writer = csv.writer(f, delimiter=',', quotechar='\'', quoting=csv.QUOTE_MINIMAL)
                writer.writerow([f"{vat_return['vatDueSales']:.2f}"])
                writer.writerow([f"{vat_return['vatDueAcquisitions']:.2f}"])
                writer.writerow([f"{vat_return['totalVatDue']:.2f}"])
                writer.writerow([f"{vat_return['vatReclaimedCurrPeriod']:.2f}"])
                writer.writerow([f"{vat_return['netVatDue']:.2f}"])
                writer.writerow([f"{vat_return['totalValueSalesExVAT']:.2f}"])
                writer.writerow([f"{vat_return['totalValuePurchasesExVAT']:.2f}"])
                writer.writerow([f"{vat_return['totalValueGoodsSuppliedExVAT']:.2f}"])
                writer.writerow([f"{vat_return['totalAcquisitionsExVAT']:.2f}"])
            return 0
        except Exception:
            print("Could not write to file!")
            return -1

    def SubmitReturn(self, vat_return) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Content-Type": "application/json"})
        self.headers.update({"Connection": "keep-alive"})
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.post(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/returns", headers=self.headers, data=json.dumps(vat_return))
        return 0

    def RetrieveLiabilities(self, start_date, end_date) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/liabilities?from={start_date}&to={end_date}", headers=self.headers)
        return 0

    def ViewPayments(self, start_date, end_date) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}organisations/vat/{self.config['DATABASE_INFO'][self.client_index]['VAT_NO']}/payments?from={start_date}&to={end_date}", headers=self.headers)
        return 0
    
    def ValidateHeaders(self):
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}test/fraud-prevention-headers/validate", headers=self.headers)
        return self.response.json()
    
    def HeaderFeedback(self):
        self.PopulateHeaders()
        self.headers.update({"Authorization": f"Bearer {self.access_token}"})
        self.response = requests.get(f"{self.config['APP_CONFIG']['BASE_URL']}test/fraud-prevention-headers/vat-mtd/validation-feedback", headers=self.headers)
        return self.response.json()


    def ShellHelp(self) -> int:
        print(f"check - check details of a GB VAT number")
        print(f"list - list all client info")
        print(f"create - create new client")
        print(f"select - select client by ID")
        print(f"retrieve - retrieve VAT obligations by status or date-range")
        print(f"return - submit VAT return for period")
        print(f"view - view submitted VAT return")
        print(f"save - save submitted VAT return to CSV")
        print(f"liability - view outstanding VAT liabilities")
        print(f"payments - view payments received by HMRC")
        print(f"exit/quit - exit the program")
        return 0

    def ShellCheck(self):
        vat_no = input('Enter VAT number: ')
        try:
            if(self.VerifyVatNumber(vat_no) < 0):
                return -1
            self.response = self.CheckVatNumber(vat_no)
            print(f"{self.response['target']['name']} - {self.response['target']['address']['line1']}, {self.response['target']['address']['postcode']}")
            return 0
        except Exception:
            print('VAT number not found!')
            return -1
        
    def ShellList(self) -> int:
        cl = self.config['DATABASE_INFO']
        if len(cl) == 0:
            print('No clients exist!')
            return -1
        for c in cl:
            act = self.active_client
            sel = ''
            #if previously selected
            if self.active_client == c['CLIENT_ID'] and self.client_index == cl.index(c):
                sel = '* '
            #select client
            print(f"{sel}{c['CLIENT_ID']} - ", end='')
            self.SelectClient(c['CLIENT_ID'])
            #search for no. outstanding obligations
            n = self.RetrieveObligationsByStatus("O", quiet=True)
            #reselect
            if act != '':
                self.SelectClient(act)
            else:
                self.SelectClient(None)
            #print
            print(f"{'NaN' if n == -1 else n} item{'s' if n != 1 else ''} outstanding")
        return 0
    
    def ShellCreate(self):
        self.client_index = ''
        self.active_client = ''
        id = str(input('Enter Client ID: '))
        cl = self.config['DATABASE_INFO']
        if len(cl) > 0:
            for c in cl:
                if id == c['CLIENT_ID']:
                    print('Client ID already exists!')
                    return -1
        vat_no = input('Enter VAT number: ')
        no = self.VerifyVatNumber(vat_no)
        if no < 0:
            return -1
        try:
            fr = int(input('Enter Flat Rate (enter 0 for standard-rate VAT scheme): '))
            if fr < 0 or fr > 20:
                print('Invalid Flat Rate!')
                return -1
        except Exception:
            print('Invalid Flat Rate!')
            return -1
        try:
            qtr = int(input('Enter VAT quarter (0=Jan, 1=Feb, 2=Mar): '))
            if qtr < 0 or qtr > 2:
                print('Invalid quarter!')
                return -1
        except Exception:
            print('Invalid quarter!')
            return -1
        st = str(input("Enter start date (YYYY-MM-DD): "))
        inp = input("Enter end date (YYYY-MM-DD, or 0 for none): ")
        try:
            end = int(inp)
            if end < 0 or end > 0:
                print('Invalid end date!')
                return -1
        except Exception:
            end = str(inp)

        newcl = {}
        newcl.update({"CLIENT_ID": id})
        newcl.update({"VAT_NO": no})
        newcl.update({"REFRESH_TOKEN": 0})
        newcl.update({"FLAT_RATE": fr})
        newcl.update({"VAT_QUARTER": qtr})
        newcl.update({"START_DATE": st})
        newcl.update({"END_DATE": end})
        newcl.update({"RETURNS": []})
        #save to config
        self.config['DATABASE_INFO'].append(newcl)
        self.SaveConfig()
        self.SelectClient(self.config['DATABASE_INFO'][self. GetClientIndex(id)]['CLIENT_ID'])

        return 0

    def ShellRetrieve(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        m = str(input(f"Select filter (open/date): "))
        if m != 'open' and m != 'date':
            print("Invalid filter!")
            return -1
        if m == 'date':
            try:
                yr = int(input("Enter year (YYYY): "))
            except Exception:
                print("Invalid year!")
                return -1
            st = f"{str(yr)}-01-01"
            en = f"{str(yr)}-12-31"
            if self.RetrieveObligationsByDate(st, en) == -1:
                print("Not found!")
        else:
            if self.RetrieveObligationsByStatus('O') == -1:
                print("Not found!")
        return 0
    
    def ShellReturn(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        pk = str(input("PeriodKey: "))
        if pk == '' or pk == 'exit' or pk == 'quit':
            return -1
        for ret in self.config['DATABASE_INFO'][self.client_index]['RETURNS']:
            if ret['PERIOD_KEY'] == pk:
                print('Already submitted!')
                return -1

        vat_return = {}
        vat_return.update({'periodKey': pk})

        fil = str(input("CSV Filename: "))
        
        if os.path.exists(fil) == False:
            print('File does not exist!')
            return -1
        name, ext =  os.path.splitext(fil)
        if ext != '.csv':
            print("Invalid return file!")
            return -1
        
        try:
            with open(fil, 'r') as f:
                reader = csv.reader(f)
                rows = []
                for row in reader:
                    rows.append(float(row[0]))
                
                if(len(rows) != 9):
                    print("Invalid return file!")
                    return -1

                vat_return.update({'vatDueSales': f"{float(rows[0]):.2f}"})
                vat_return.update({'vatDueAcquisitions': f"{float(rows[1]):.2f}"})
                vat_return.update({'totalVatDue': f"{float(rows[2]):.2f}"})
                vat_return.update({'vatReclaimedCurrPeriod': f"{float(rows[3]):.2f}"})
                vat_return.update({'netVatDue': f"{abs(float(rows[4])):.2f}"})
                vat_return.update({'totalValueSalesExVAT': f"{round(rows[5])}"})
                vat_return.update({'totalValuePurchasesExVAT': f"{round(rows[6])}"})
                vat_return.update({'totalValueGoodsSuppliedExVAT': f"{round(rows[7])}"})
                vat_return.update({'totalAcquisitionsExVAT': f"{round(rows[8])}"})

                self.DisplayReturn(vat_return)

        except Exception:
            print("Invalid return file!")
            return -1

        print("CSV imported successfully!")
        fin = str(input("Finalised? [Y/n]: "))
        if fin == 'Y':
            print('When you submit this VAT information you are making a legal declaration that the information is true and complete.')
            print('A false declaration can result in prosecution.')
            cfm = str(input("Are you sure you want to submit a finalised return? [Y/n]: "))
            if cfm != 'Y':
                return -1
            vat_return.update({'finalised': True})
            print("Submitting VAT return...")
            if self.SubmitReturn(vat_return) == 0:
                try:
                    print(self.response.json()['code'])
                    return -1
                except Exception:
                    return_info = {}
                    return_info.update({"PERIOD_KEY": pk})
                    return_info.update({"RECEIPT": self.response.json()})
                    self.config['DATABASE_INFO'][self.client_index]['RETURNS'].append(return_info)
                    self.SaveConfig()
                    return 0
        
    def ShellView(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        pk = str(input('Enter Period Key: '))
        self.RetrieveReturn(pk)
        return 0

    def ShellSave(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        pk = str(input('Enter Period Key: '))
        if self.RetrieveReturn(pk, True) == 0:
            print("Saved!")
        return 0

    def ShellLiabilities(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        try:
            yr = int(input("Enter year (YYYY): "))
        except Exception:
            print("Invalid year!")
            return -1
        st = f"{str(yr)}-01-01"
        en = f"{str(yr)}-12-31"
        self.RetrieveLiabilities(st, en)
        try:
            print(self.response.json()['code'])
            return -1
        except Exception:
            first = True
            for paym in self.response.json()['liabilities']:
                if paym['outstandingAmount'] != 0:
                    if first == True:
                        print(f" Amount (£)\tDue")
                        first = False
                    print("{:>10}".format(f"{paym['outstandingAmount']:,.2f}"), end='')
                    try:
                        print(f"\t{paym['due']}")
                    except Exception:
                        print()
            return 0

    def ShellPayments(self) -> int:
        if self.active_client == '' or self.client_index == None:
            print('No client selected!')
            return -1
        try:
            yr = int(input("Enter year (YYYY): "))
        except Exception:
            print("Invalid year!")
            return -1
        st = f"{str(yr)}-01-01"
        en = f"{str(yr)}-12-31"
        self.ViewPayments(st, en)
        try:
            print(self.response.json()['code'])
            return -1
        except Exception:
            print(f" Amount (£)\tDate")
            for paym in self.response.json()['payments']:
                print("{:>10}".format(f"{paym['amount']:,.2f}"), end='')
                try:
                    print(f"\t{paym['received']}")
                except Exception:
                    print()
            return 0


    def Run(self):
            try:
                while True:
                    cmd = input('Enter Command: ')
                    if cmd == 'help' or cmd == '':
                        self.ShellHelp()
                    elif cmd == 'check':
                        self.ShellCheck()
                    elif cmd == 'list':
                        self.ShellList()
                    elif cmd == 'create':
                        self.ShellCreate()
                    elif cmd == 'select':
                        id = str(input('Enter Client ID: '))
                        self.SelectClient(id)
                    elif cmd == 'retrieve':
                        self.ShellRetrieve()
                    elif cmd == 'return':
                        self.ShellReturn()
                    elif cmd == 'view':
                        self.ShellView()
                    elif cmd == 'save':
                        self.ShellSave()
                    elif cmd == 'liability':
                        self.ShellLiabilities()
                    elif cmd == 'payments':
                        self.ShellPayments()
                    elif cmd == 'exit' or cmd == 'quit':
                        sys.exit(0)
                    else:
                        print('Invalid command! Type \'help\' for list of commands')
            except KeyboardInterrupt:
                sys.exit(0)

