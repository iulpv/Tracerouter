from scapy.config import conf
conf.auto_fragment = False
import time
from scapy.sendrecv import sr1, sr, sendp
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.all import Raw
from scapy.volatile import RandShort, RandString
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest


class Traceroute:
    def __init__(self, input_data):
        self.ip = input_data.IP_ADDRESS
        self.timeout = input_data.t
        self.protocol = input_data.protocol
        self.ttl = input_data.ttl
        self.port = input_data.p
        self.interval = input_data.i
        self.size = input_data.s
        self.retry = input_data.r

    def find_route(self):
        pack = self.check_protocol()
        for num_ttl in range(1, self.ttl + 1):
            start_time = time.perf_counter()
            ans = sr1(pack(num=num_ttl), verbose=0, timeout=self.timeout, retry=self.retry)
            elapsed_time = time.perf_counter() - start_time
            mtu = ''
            if ans is not None:
                mtu = self.define_mtu(ans.src)
            self.get_ans(ans=ans, elapsed_time=elapsed_time, num_ttl=num_ttl, mtu=mtu)
            if ans and ans.src == self.ip:
                break
            time.sleep(self.interval)

    def create_tcp_pack(self, num):
        if self.port is None:
            raise ValueError("введите порт")
        if ':' in self.ip:
            return IPv6(dst=self.ip, hlim=num) / TCP(dport=self.port) / Raw(RandString(size=self.size))
        return IP(dst=self.ip, ttl=num) / TCP(dport=self.port) / Raw(RandString(size=self.size))

    def create_udp_pack(self, num):
        if self.port is None:
            raise ValueError("введите порт")
        if ':' in self.ip:
            return IPv6(dst=self.ip, hlim=num) / UDP(dport=self.port, sport=RandShort()) / Raw(
                RandString(size=self.size))
        return IP(dst=self.ip, ttl=num) / UDP(sport=RandShort(), dport=self.port) / Raw(RandString(size=self.size))

    def create_icmp_pack(self, num):
        if ':' in self.ip:
            return IPv6(dst=self.ip, hlim=num) / ICMPv6EchoRequest() / Raw(RandString(size=self.size))
        return IP(dst=self.ip, ttl=num) / ICMP() / Raw(RandString(size=self.size))

    def check_protocol(self):
        if self.protocol == 'tcp':
            return self.create_tcp_pack
        elif self.protocol == 'udp':
            return self.create_udp_pack
        elif self.protocol == 'icmp':
            return self.create_icmp_pack
        else:
            raise ValueError('некорректный протокол')

    def get_ans(self, ans, elapsed_time, num_ttl, mtu):
        if ans is None:
            print(f'{num_ttl} *')
            return
        print(f'{num_ttl} {ans.src} {int(elapsed_time * 1000)}ms {mtu}')

    def define_mtu(self, ip):
        l = 100
        r = 5000
        while l <= r:
            mid = l + (r - l) // 2
            if l == r:
                return mid
            if ':' in ip:
                p = IPv6(dst=ip) / ICMPv6EchoRequest() / ('x' * mid)
            else:
                p = IP(dst=ip, flags="DF") / ICMP() / ('x' * mid)
            try:
                sendp(p, verbose=0)
            except OSError:
                r = mid - 1
            else:
                l = mid + 1
