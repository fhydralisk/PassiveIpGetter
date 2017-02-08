import commands
import threading
import time
import re


def format_timestamp(timestamp):
    l_time = time.gmtime(timestamp + 8 * 60 * 60)
    return time.strftime("%Y-%m-%d %H:%M:%S", l_time)


class MacAddr(object):
    def __init__(self, mac):
        self.mac_digit = []
        if isinstance(mac, basestring):
            element = r"([\da-fA-F]{1,2})"
            pattern_element = [element for i in range(6)]
            if mac.__contains__(":"):
                splitter = ":"
            elif mac.__contains__("-"):
                splitter = "-"
            else:
                splitter = ""

            pattern = re.compile(splitter.join(pattern_element))
            mr = pattern.match(mac)
            if mr is None:
                raise ValueError
            else:
                for i in range(1, 7):
                    self.mac_digit.append(int(mr.group(i), 16))

        elif isinstance(mac, MacAddr):
            if len(mac.mac_digit) != 6:
                raise IndexError
            else:
                self.mac_digit = list(mac.mac_digit)

        else:
            raise TypeError

    def __hash__(self):
        return str(self).__hash__()

    def __str__(self):
        if len(self.mac_digit) == 6:
            return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(self.mac_digit)
        else:
            return object.__str__(self)

    def __eq__(self, other):
        if isinstance(other, MacAddr):
            return self.mac_digit == other.mac_digit
        else:
            return False


class IPAddrScanner(object):
    def __init__(self, interval, net_seg, fallback_user):
        self.interval = interval
        self.net_seg = net_seg
        self.fallback_user = fallback_user
        '''
        mac_to_ip:
        mac_addr : {IP: last_update}
        '''
        self.mac_to_ip = {}
        self.last_update = 0
        self.is_updating = False
        self.task = None
        self.tick = 0

    def run(self):
        while True:
            if self.tick <= 0:
                result = self.do_update()
                self.last_update = int(time.time())
                self.combine_result(result)
                self.tick = self.interval * 60
            else:
                self.tick -= 1
            time.sleep(1)

    def run_in_thread(self):
        if self.task is None:
            self.task = threading.Thread(target=self.run)
            self.task.setDaemon(True)
            self.task.start()

    def do_update(self):
        self.is_updating = True
        commands.getstatusoutput("arp -n|awk '/^[1-9]/{print \"arp -d  \" $1}'|sh")
        status, output_nmap = commands.getstatusoutput('su - %s -c "nmap -sn %s"' % (self.fallback_user, self.net_seg))
        status, output_arp = commands.getstatusoutput("arp -an| grep -v incomplete | awk -F' ' '{print $2\" \"$4}'")
        self.is_updating = False
        nmap_output = self.parse_nmap_output(output_nmap)
        arp_output = self.parse_arp_output(output_arp)
        final_output = nmap_output
        for arp_entry in arp_output:
            if arp_entry in final_output:
                final_output[arp_entry].union(arp_output[arp_entry])
            else:
                final_output[arp_entry] = arp_output[arp_entry]

        return final_output

    def do_update_now(self):
        self.tick = 0

    @staticmethod
    def parse_arp_output(output):
        pattern = re.compile(r"\((\d+.\d+.\d+.\d+)\)\s([\da-fA-F]+:[\da-fA-F]+:[\da-fA-F]+:[\da-fA-F]+:[\da-fA-F]+:[\da-fA-F]+)")
        lines = output.split("\n")
        mac_to_ip = {}
        for l in lines:
            mr = pattern.match(l)
            if mr is not None:
                ip_str = mr.group(1)
                mac_str = mr.group(2)
                mac = MacAddr(mac_str)
                if mac not in mac_to_ip:
                    mac_to_ip[MacAddr(mac_str)] = set([])
                mac_to_ip[MacAddr(mac_str)].add(ip_str)
        return mac_to_ip
    
    @staticmethod
    def parse_nmap_output(output):
        mac_to_ip = {}
        sgs = output.split('Nmap scan report for ')
        pattern = re.compile(
                r'(?#ip address)((?:\d{1,3}\.){3}\d{1,3})\n.*\nMAC Address: (?#mac address)((?:[\da-fA-F]{2}:){5}[\da-fA-F]).*\n'
            )
        for sg in sgs:
            mr = pattern.match(sg)
            if mr is not None:
                ip_str = mr.group(1)
                mac_str = mr.group(2)
                mac = MacAddr(mac_str)
                if mac not in mac_to_ip:
                    mac_to_ip[MacAddr(mac_str)] = set([])
                mac_to_ip[MacAddr(mac_str)].add(ip_str)

        return mac_to_ip

    def combine_result(self, new_result):
        for mac, ips in new_result.items():
            if mac not in self.mac_to_ip:
                self.mac_to_ip[mac] = {}
            for ip in ips:
                self.mac_to_ip[mac][ip] = self.last_update
        for mac, ip_dict in self.mac_to_ip.items():
            for ip, last_upd in ip_dict.items():
                if self.last_update - last_upd > 240 * self.interval:
                    del self.mac_to_ip[mac][ip]

            if len(self.mac_to_ip[mac]) == 0:
                del self.mac_to_ip[mac]

    def get_rpc_query_addr_result(self, macaddr):
        try:
            return {"result": {k: format_timestamp(v) for k, v in self.mac_to_ip[MacAddr(macaddr)].items()}}
        except KeyError or ValueError:
            return {"result": {}}

    def get_rpc_query_status_result(self):
        return {
            "Last_update": format_timestamp(self.last_update),
            "Next_update": format_timestamp(self.last_update + self.interval * 60),
            "Time_left": self.tick,
            "Is_updating": self.is_updating
        }

    def get_rpc_query_arp_list(self):
        return {str(k): v for k, v in self.mac_to_ip.items()}

    def get_rpc_query_ip_for_mac(self, ipaddr):
        for mac, ips in self.mac_to_ip.items():
            if ipaddr in ips:
                return {"result": {"mac": str(mac)}}

        return {"result": {}}

    @staticmethod
    def rpc_wol_mac(macaddr):
        from WOLSender import run as wol_send
        if wol_send(macaddr):
            return {"result": "OK"}
        else:
            return {"result": "Fail"}
