class frameInst:

    def parse(self, input):
        """s = input[0:6]
        d = input[6:12]
        e = input[12:14]"""
        p = input[14:]
        return p

    def __init__(self, input):
        self.src,\
        self.dst,\
        self.ethver,\
        self.payload = self.parse(input)


def parse(input):
        """s = input[0:6]
        d = input[6:12]
        e = input[12:14]"""
        p = input[14:]
        return p


class etherInstance:
    """Instance for connection establishment"""

    def sendeth(self, src, dst, eth_type, payload):
        """Send raw Ethernet packet on interface."""
        assert(len(src) == len(dst) == 6)
        assert(len(eth_type) == 2)
        # --
        from socket import socket, AF_PACKET, SOCK_RAW
        s = socket(AF_PACKET, SOCK_RAW)
        s.bind((self.interface, 0))
        checksum = b''
        return s.send(src + dst + eth_type + payload + checksum)

    def recveth(self, k):
        """Recieve k Ethernet packet on interface"""
        import socket
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.bind((self.interface, 0))
        i = 0
        fr = ()
        frame = b''
        try:
            while i < k:
                buffsize = 1600
                fr += (s.recvfrom(buffsize)[0],)
                i += 1
        except:
            return []
        for f in fr:
            t = parse(f)
            frame += t
        return frame

    def __init__(self, i):
        self.interface = i


class thread:

    def __init__(self):
        trafficType = ['ping', 'random']
        from random import randint
        self.mac = b''.join([(randint(0, 255)).to_bytes(1, 'big') for _ in range(0, 6)])
        self.trafficType = trafficType[0]  # trafficType[randint(0, 10) % 2]

    def start(self):
        from random import randint
        from time import sleep
        try:
            while True:
                e = etherInstance('vboxnet0')  # replace by actual interface
                fr = e.recveth(1)
                if fr[12:14] == b'\x08\x01':
                    pay = fr[14:]
                    src_addr = b''.join([(randint(0, 255)).to_bytes(1, 'big') for _ in range(0, 6)])
                    dst_addr = b''.join([(randint(0, 255)).to_bytes(1, 'big') for _ in range(0, 6)])
                    ethertype = b'\x08\x01'
                    e.sendeth(src_addr, dst_addr, ethertype, pay[0:3])

                s = randint(1, 5)
                sleep(s)
        except:
            return


class trafficReflector:

    def __init__(self, t):
        self.threads = [thread() for _ in range(0, t)]

    def generate(self):
        from threading import Thread
        for e in self.threads:
            task = Thread(target=e.start, args=())
            task.start()



if __name__ == "__main__":
    generator = trafficReflector(2)
    generator.generate()
