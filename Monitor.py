
class Monitor():
    '''Newtork entity of airmon-ng for promiscuous listening'''
    def __init__(self, logger):
        '''
        input:
            logger - logging object
        fields:
            logger

        '''
        self.log_client = logger

    @property
    def logger(self):
        return self.log_client

    def get_mon_iface_name(self, iwfaces):
        from re import findall
        try:
            new_iface = findall(r'monitor\smode\s.+enabled\son\s.+', iwfaces)[0]
            new_iface = findall(r'[a-z0-9]+$', new_iface)[0]
            return new_iface

        except Exception as e:
            self.log_client.addToLine('Monitors.get_mon_iface_name',\
                "no new monitor interface found " + str(e) + '" with ' + iwfaces, 'error')
            return ''

    def push(self, netw_iface, channel = 0):
        '''
        add new monitor
        input:
            netw_iface - name of used network interface
        output:
            new monitor interface 
        '''
        import subprocess
        from random import randint
        air_out = subprocess.run(
            [
                "airmon-ng",
                "start",
                netw_iface,
                str(randint(1, 14)) if channel == 0 else channel
            ],
            capture_output=True
            )
        air_out = air_out.stdout.decode('utf-8')
        new_iface = self.get_mon_iface_name(air_out)
        return new_iface

    def pop(self, mon):
        import subprocess
        subprocess.run(["airmon-ng", "stop", mon], capture_output=False)

