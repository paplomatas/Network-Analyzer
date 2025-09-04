# tests/test_filter.py

import pytest
from network_analyzer.capture.filter import PacketFilter

def test_protocol_filter():
    pf = PacketFilter()
    pkt = {'protocol': 'TCP'}
    assert pf.apply_filters(pkt, ['tcp'])

def test_ip_filters():
    pf = PacketFilter()
    pkt = {'src_ip': '192.168.0.1', 'dst_ip': '10.0.0.1'}
    assert pf.apply_filters(pkt, [('ip', '10.0.0.1')])
    assert pf.apply_filters(pkt, [('src_ip', '192.168.0.1')])
    assert not pf.apply_filters(pkt, [('dst_ip', '8.8.8.8')])

def test_size_filters():
    pf = PacketFilter()
    pkt = {'size': 400}
    assert pf.apply_filters(pkt, [('size', 400)])
    assert pf.apply_filters(pkt, [('size_gt', 300)])
    assert pf.apply_filters(pkt, [('size_lt', 500)])
    assert not pf.apply_filters(pkt, [('size', 999)])
