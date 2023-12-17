from scapy.layers.inet import IP, TCP
from pyp0f.database import DATABASE
from pyp0f.fingerprint import fingerprint_mtu, fingerprint_tcp, fingerprint_http
from pyp0f.fingerprint.results import MTUResult, TCPResult, HTTPResult

DATABASE.load()  # Load the fingerprints database

def perform_mtu_fingerprinting():
    google_packet = IP() / TCP(options=[("MSS", 1430)])
    mtu_result: MTUResult = fingerprint_mtu(google_packet)
    return mtu_result

def perform_tcp_fingerprinting():
    linux_packet = IP(tos=0x10, flags=0x02, ttl=58) / TCP(
        seq=1,
        window=29200,
        options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (177816630, 0)), ("NOP", None), ("WScale", 7)],
    )
    tcp_result: TCPResult = fingerprint_tcp(linux_packet)
    return tcp_result

def perform_http_fingerprinting():
    apache_payload = b"HTTP/1.1 200 OK\r\nDate: Fri, 10 Jun 2011 13:27:01 GMT\r\nServer: Apache\r\nLast-Modified: Thu, 09 Jun 2011 17:25:43 GMT\r\nExpires: Mon, 13 Jun 2011 17:25:43 GMT\r\nETag: 963D6BC0ED128283945AF1FB57899C9F3ABF50B3\r\nCache-Control: max-age=272921,public,no-transform,must-revalidate\r\nContent-Length: 491\r\nConnection: close\r\nContent-Type: application/ocsp-response\r\n\r\n"
    http_result: HTTPResult = fingerprint_http(apache_payload)
    return http_result
