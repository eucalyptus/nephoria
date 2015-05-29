

import re
import socket
import subprocess
import sys
import time
from cloud_utils.system_utils import local


def test_port_status(ip,
                     port,
                     timeout=5,
                     tcp=True,
                     recv_size=0,
                     send_buf=None,
                     debug=None,
                     verbose=True):
        '''
        Attempts to connect to tcp port at ip:port within timeout seconds

        :param ip: remote ip/hostname to attempt to connect to
        :param port: remote port to connect to
        :param tcp: Use tcp in this test
        :param recv_size: size of buffer to read from socket
        :param send_buf: buffer to send
        :param debug: bool, print debug info w/ 'print'
        :param verbose: bool, print verbose info
        :returns buffer read in
        '''
        ret_buf = ""
        if verbose:
            if not debug:
                def debug(msg):
                    print str(msg)
        else:
            def debug(msg):
                pass

        debug('test_port_status, ip:'+str(ip)+', port:'+str(port)+', TCP:'+str(tcp))
        if tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.settimeout(timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            if tcp:
                s.connect((ip, port))
            else:
                # for UDP always try send
                if send_buf is None:
                    send_buf = "--TEST LINE--"
            if send_buf is not None:
                s.sendto(send_buf, (ip, port))
            if recv_size:
                ret_buf = s.recv(recv_size)
        except socket.error, se:
            debug('test_port_status failed socket error:'+str(se[0]))
            # handle specific errors here, for now just for debug...
            ecode = se[0]
            if ecode == socket.errno.ECONNREFUSED:
                debug("test_port_status: Connection Refused")
            if ecode == socket.errno.ENETUNREACH:
                debug("test_port_status: Network unreachable")
            if ecode == socket.errno.ETIMEDOUT or ecode == "timed out":
                debug("test_port_status: Connect to " + str(ip) + ":" + str(port) + " timed out")
            raise se
        except socket.timeout, st:
            debug('test_port_status failed socket timeout')
            raise st
        finally:
            s.settimeout(None)
            s.close()
        debug('test_port_status, success')
        return ret_buf


def scan_port_range(ip, start, stop, timeout=1, tcp=True):
    '''
    Attempts to connect to ports, returns list of ports which accepted a connection

    :param ip: remote ip to scan
    :param start: lower end of port range to scan
    :param stop: upper end of port range to scan
    :param timeout: int timeout in seconds per port being scanned
    :param tcp: bool, if true TCP is used, else UDP
    :return list of ports which did not fault (connected) during scan
    '''
    ret = []
    for x in xrange(start, stop+1):
        try:
            sys.stdout.write("\r\x1b[K"+str('scanning:'+str(x)))
            sys.stdout.flush()
            test_port_status(ip, x, timeout=timeout, tcp=tcp, verbose=False)
            ret.append(x)
        except socket.error, se:
            pass
    return ret


def ping(address, poll_count=10, interval=2, logger=None):
        """
        :param: Ping an IP and poll_count times (Default = 10)
        :param: address      Hostname to ping
        :param: poll_count   The amount of times to try to ping the hostname with interval second
                     gaps in between
        :param: logger: optional logger to send debug and critical output to
        :returns: boolean True if ping succeeds, else false for failure
        """
        if logger:
            critical = logger.critical
            debug = logger.debug
        else:
            def debug(msg):
                print str(msg)

            def critical(msg):
                print sys.stderr, str(msg)

        if re.search("0.0.0.0", address):
            critical("Address is all 0s and will not be able to ping it")
            return False
        debug("Attempting to ping " + address)
        for x in xrange(0, poll_count):
            if x:
                debug('sleeping for {0} seconds'.format(interval))
                time.sleep(interval)
            try:
                local("ping -c 1 " + address)
                debug("Was able to ping address")
                return True
            except subprocess.CalledProcessError as CPE:
                debug('Output:' + str(CPE.output))
                debug('Ping attempt {0}/{1} failed, err:{2}'
                      .format(x, poll_count, str(CPE)))
        critical("Was unable to ping address")
        return False


def is_address_in_network(ip_addr, network):
        """

        :param ip_addr: Ip address ie: 192.168.1.5
        :param network: Ip network in cidr notation ie: 192.168.1.0/24
        :return: boolean true if ip is found to be in network/mask, else false
        """
        ip_addr = str(ip_addr)
        network = str(network)
        # Check for 0.0.0.0/0 network first...
        rem_zero = network.replace('0','')
        if not re.search('\d', rem_zero):
            return True
        ipaddr = int(''.join([ '%02x' % int(x) for x in ip_addr.split('.') ]), 16)
        netstr, bits = network.split('/')
        netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        return (ipaddr & mask) == (netaddr & mask)