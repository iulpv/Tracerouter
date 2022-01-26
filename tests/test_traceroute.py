from traceroute import Traceroute
from types import SimpleNamespace
import pytest


def test_check_protocol():
    args = SimpleNamespace(IP_ADDRESS='1.1.1.1', i=0, p=80, protocol='tcp', r=3, s=40, t=2, ttl=30)
    trace = Traceroute(args)
    assert trace.check_protocol() == trace.create_tcp_pack


def test_tcp_failed():
    args = SimpleNamespace(IP_ADDRESS='1.1.1.1', i=0, p=None, protocol='tcp', r=3, s=40, t=2, ttl=30)
    trace = Traceroute(args)
    with pytest.raises(ValueError) as exception:
        trace.create_tcp_pack(num=1)
    assert exception.type == ValueError


def test_udp_failed():
    args = SimpleNamespace(IP_ADDRESS='1.1.1.1', i=0, p=None, protocol='udp', r=3, s=40, t=2, ttl=30)
    trace = Traceroute(args)
    with pytest.raises(ValueError) as exception:
        trace.create_udp_pack(num=1)
    assert exception.type == ValueError


def test_icmp():
    args = SimpleNamespace(IP_ADDRESS='1.1.1.1', i=0, p=None, protocol='icmp', r=3, s=40, t=2, ttl=30)
    trace = Traceroute(args)
    assert trace.check_protocol() == trace.create_icmp_pack


def test_different_protocol_failed():
    args = SimpleNamespace(IP_ADDRESS='1.1.1.1', i=0, p=None, protocol='tls', r=3, s=40, t=2, ttl=30)
    trace = Traceroute(args)
    with pytest.raises(ValueError) as exception:
        trace.check_protocol()
    assert exception.type == ValueError




