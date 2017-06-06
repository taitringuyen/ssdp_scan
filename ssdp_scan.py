#!/usr/bin/python

import os
import sys
import logging
#import platform
import struct
import socket
import select
#import threading
import time
import httplib
try:
    import cStringIO as StringIO
except ImportError:
    import StringIO


log = logging.getLogger('ssdp_scan')
logging.basicConfig()
log.setLevel(logging.DEBUG)

SSDP_MULTICAST_ADDR = '239.255.255.250'
SSDP_PORT = 1900
SSDP_PACKET_SIZE = 1024

SSDP_QUERY_STRING = "\r\n".join([
    'M-SEARCH * HTTP/1.1',
    'HOST: %(host_ip)s:%(host_port)d',
    'MAN: "ssdp:discover"',
    'ST: %(st)s',
    'MX: %(mx)d',
    '',
    '',
    ])

class Response(httplib.HTTPResponse):
    """
    NB if this is an response that does not start with 'HTTP/1.1 200 OK', stdlib httplib.HTTPResponse() will fail to find anything.
    """
    def __init__(self, response_text):
        self.fp = StringIO.StringIO(response_text)
        self.debuglevel = 0
        self.strict = 0
        self.msg = None
        self._method = None
        self.begin()


def process_ssdp_result_message(in_bytes):
    """Returns tuple of unique key and value(s)
    Assumes we can use Python httplib library to
    process HTTP Response.
    """
    response = Response(in_bytes)
    headers = response.getheaders()
    header_dict = dict(headers)
    # find something unique
    location = header_dict['location']
    return (location, header_dict)


def simple_http_headers_processor(in_bytes, unique_key='location'):
    """Returns tuple of unique key and value(s)
    pilight v5 does NOT return spaces after header colon and httplib freaks out.
    This simply using naive string spliting to process HTTP headers.
    This is not intended to be 100% compliant with http://www.w3.org/TR/discovery-api/
    """
    #print '-' * 65
    #print repr(in_bytes)
    #print '-' * 65
    header_dict = {}
    header_list = in_bytes.split('\r\n')
    #assert 'NOTIFY * HTTP/1.1' in header_list[0] or 'M-SEARCH * HTTP/1.1' in header_list[0], repr(header_list[0][:30])
    header_list.pop(0)
    for line in header_list:
        line = line.strip()
        if line:
            try:
                key, value = line.split(':', 1)
                key = key.lower()
                value = value.strip()
                header_dict[key] =  value
            except ValueError:
                # Probably did NOT split correctly, i.e. not a "name: value" pair
                pass
    if unique_key:
        location = header_dict['location']
        return (location, header_dict)
    else:
        return header_dict


def ssdp_discover(service_name='ssdp:all', timeout=3, host_ip=SSDP_MULTICAST_ADDR, host_port=SSDP_PORT, process_func=simple_http_headers_processor):
    """SSDP search client. Find all/specified ssdp services
    Sample service names:
        service_name='ssdp:all'  # find all, no filter
        service_name='upnp:rootdevice'  # find all, no filter
        service_name='uuid:...specific name....', filter to name
    
    host_ip can be multicast or a specific ip address for unicast
    
    Currently retries are not attempted
    """
    assert 1<= timeout <= 5
    ssdp_values = {
        'host_ip': host_ip,  # unicast (specific ip) or multicast
        'host_port': host_port,  # almost always 1900
        'st': service_name,
        'mx': timeout,
    }
    ssdp_query_string = SSDP_QUERY_STRING % ssdp_values
    log.debug('ssdp query: %r', ssdp_query_string)
    result = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    sock.sendto(ssdp_query_string, (host_ip, host_port))
    location = 0  # DEBUG
    while 1:
        # TODO handle timeout math
        rlist, wlist, elist = select.select([sock], [], [], timeout)
        if rlist:
            packet_bytes = sock.recv(SSDP_PACKET_SIZE)
            log.debug('ssdp response: %r', packet_bytes)
            location, header_dict = process_func(packet_bytes)
            result[location] = header_dict
        else:
            break

    return result

def show_devices():
    log.setLevel(logging.INFO)
    #log.setLevel(logging.DEBUG)  # DEBUG
    log.info('Looking for published SSDP services on network')
    services = ssdp_discover()
    for x in services:
        print '-' * 65
        print x
        print services[x]['server']
        print services[x]


##################################

def main(argv=None):
    if argv is None:
        argv = sys.argv

    show_devices()

    return 0


if __name__ == "__main__":
    sys.exit(main())
