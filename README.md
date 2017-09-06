# 1.Summary.
The collector is a tool for grabbing EAPOL packets. As you would know, you need only half of WPA handshake to start cracking Access Point's password. So you need the packets. This tool allows you to:
1)Find all achievable APs around you and send deauth packets to its clients (the tool collect a dump of packets and search for beacon frames or for probe response frames, as you can see on a picture below).

![response](https://pp.userapi.com/c621707/v621707255/13ee8/JSyrZzYMggU.jpg)

2)Listen for probe frames. If a smartphone (for example) is not connected to AP, but its adapter is switched on, is sends probe frames. The frames contains ESSID of some AP (smartphone knows password of the AP), as you can see on a picture below.

![request](https://pp.userapi.com/c621707/v621707255/13eef/VCp850H24YU.jpg)

# 2.Installation and usage.
Install python interpreter using one of the following links:
* https://www.python.org/downloads/source/ (Linux)
* https://www.python.org/downloads/windows/ (Windows)
* https://www.python.org/downloads/mac-osx/ (Mac-OSx)
* https://www.python.org/download/other/ (Other ones)

Install pip for Python3 (for Linux only).
```
sudo apt-get install python3-setuptools
sudo easy_install3 pip
```

You are to install the pcapfile module to guarantee correct work of the tool.
```
pip install -r requirements.txt
```
Then you are able to use the converter. The possible commands:
1. Launch collector: wlan0 interface is for grabbing all wireless packets, wlan 1 is for raising APs.
```
python listen.py -l wlan0 -s wlan1  
```
2. Help.
```
python listen.py -h
```
Look at launch example paragraph if you have any doubts about program usage.
# 3.Launch example.
If installation was successful, you just need to launch the program as the following one:
```
python listen.py -s wlan0 -l wlan1
```
The script creates two folder:
* dumps (a directory for dumps of packets which was grabbed by -s interface)

![dumps](https://pp.userapi.com/c621707/v621707543/16ceb/ucy1oMvEkDE.jpg)

* logs (a directory for dumps of packets which was grabbed by -l interface).
