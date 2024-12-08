#!/usr/bin/env python

import logging
import socket
import re
import sys
import time
from struct import unpack
import struct
import select
import optparse
import errno
# import relay
buffer_size = 4096
delay = 0.0001
socks_server_reply_success = b'\x00\x5a\xff\xff\xff\xff\xff\xff'
socks_server_reply_fail = b'\x00\x5b\xff\xff\xff\xff\xff\xff'
relay_timeout = 160
banner = b'RPIVOT'
banner_response = b'TUNNELRDY'

COMMAND_CHANNEL = 0

CHANNEL_CLOSE_CMD = b'\xcc'
CHANNEL_OPEN_CMD = b'\xdd'
FORWARD_CONNECTION_SUCCESS = b'\xee'
FORWARD_CONNECTION_FAILURE = b'\xff'
CLOSE_RELAY = b'\xc4'
PING_CMD = b'\x70'

cmd_names = {
    b'\xcc': b'CHANNEL_CLOSE_CMD',
    b'\xdd': b'CHANNEL_OPEN_CMD',
    b'\xee': b'FORWARD_CONNECTION_SUCCESS',
    b'\xff': b'FORWARD_CONNECTION_FAILURE',
    b'\xc4': b'CLOSE_RELAY',
    b'\x70': b'PING_CMD'
}
import threading
# from common import create_logger, ls, Relay, RelayMainError
def create_logger(logger_name, threads=False, verbose=False, log_file=''):
    log = logging.getLogger(logger_name)

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%H:%M:%S')
    if threads:
        formatter = logging.Formatter('%(asctime)s - [%(threadName)s] - %(levelname)s - %(message)s', '%H:%M:%S')

    if verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    if log_file:
        ch = logging.FileHandler(log_file)
        ch.setFormatter(formatter)
        log.addHandler(ch)

    return log


def b(byte):
    """

    @param byte:
    @return: byte in '\x00' format
    """
    if sys.version_info[0] == 2:
        return byte
    return byte.to_bytes(1, byteorder='big')


def to_hex(s):
    if sys.version_info[0] == 2:
        return s.encode('hex')
    if isinstance(s, str):
        s = s.encode()
    return s.hex()


def ls(l):
    """
    List to string
    @param l: iterable
    @return: string
    """
    if not l:
        return '[]'
    return ', '.join([str(x) for x in l])


log = create_logger(__name__)


class RelayMainError(Exception):
    pass


class Relay(object):
    def __init__(self, command_socket):
        self.input_connections = list()
        self.channels = {}
        self.last_ping = time.time()
        self.remote_side_is_down = False
        self.command_socket = command_socket
        self.id_by_socket = {}

        self.ping_delay = 100
        self.relay_timeout = 60

        self.input_connections.append(command_socket)

    def ping_worker(self):
        raise NotImplementedError

    @staticmethod
    def close_sockets(sockets):
        for s in sockets:
            try:
                s.close()
            except socket.error as err:
                log.warning(err)
                pass

    @staticmethod
    def __recvall(sock, data_len):
        """
        Receive excactly lata_len bytes from the socket.
        @return: bytestring
        """
        buf = b''
        while True:
            buf += sock.recv(data_len - len(buf))
            if len(buf) == data_len:
                break
            time.sleep(0.0001)
        assert (data_len == len(buf))
        return buf

    def shutdown(self):
        self.remote_side_is_down = True
        self.close_sockets(self.input_connections)

    @staticmethod
    def parse_socks_header(data):
        """
        source: https://www.openssh.com/txt/socks4.protocol
        @raise: RelayMainError
        """
        try:
            (vn, cd, dstport, dstip) = struct.unpack('>BBHI', data[:8])
        except struct.error:
            raise RelayMainError('Invalid socks header! Got data: {0}'.format(repr(data)))

        if vn != 4:
            raise RelayMainError('Invalid socks header! Only Socks4 supported')

        str_ip = socket.inet_ntoa(struct.pack(">L", dstip))
        log.debug('Got header: socks version: {0}; socks command: {1}; dst: {2}:{3}'.format(vn, cd, str_ip, dstport))
        return str_ip, dstport

    def get_channel_data(self):
        """
        Getting data from the command socket (from client or from server).
        @return: tuple[int,bytes]
        @raise: RelayMainError
        """
        try:
            tlv_header = self.__recvall(self.command_socket, 4)
            channel_id, tlv_data_len = struct.unpack('<HH', tlv_header)
            data = self.__recvall(self.command_socket, tlv_data_len)
        except socket.error as err:
            (code, msg) = err.args
            raise RelayMainError('Exception on receiving tlv message from remote side.'
                                 'Errno: {} Msg: {}. Exiting...'.format(errno.errorcode[code], msg))
        return channel_id, data

    def _set_channel(self, sock, channel_id):
        self.channels[channel_id] = sock
        self.id_by_socket[sock] = channel_id
        return channel_id

    def unset_channel(self, channel_id):
        sock = self.channels[channel_id]
        del self.id_by_socket[sock]
        del self.channels[channel_id]

    def relay(self, data, to_socket):
        """
        Common methon sending data to a socket.
        @param to_socket: SOCKS client socket or proxy client socket
        @raise: RelayMainError
        """

        try:
            to_socket.send(data)
        except socket.error as err:
            (code, msg) = err.args
            log.debug('Exception on relaying data to socket {}. '
                      'Errno: {} Msg: {}'.format(to_socket, errno.errorcode[code], msg))

            if to_socket == self.command_socket:
                raise RelayMainError

            channel_id = self.id_by_socket[to_socket]
            log.debug('[channel {}] Closing socket...'.format(channel_id))
            to_socket.close()
            self.input_connections.remove(to_socket)
            self.unset_channel(channel_id)
            self.send_proxy_cmd(CHANNEL_CLOSE_CMD, channel_id)

    #
    # Handle commands templates
    #

    def close_channel_hdl(self, channel_id):
        raise NotImplementedError

    def open_channel_hdl(self, data):
        """
        For client class only.
        """
        raise NotImplementedError

    def forward_connection_success_hdl(self, channel_id):
        """
        For server class only.
        """
        raise NotImplementedError

    def forward_connection_failue_hdl(self, channel_id):
        """
        For server class only.
        """
        raise NotImplementedError

    def ping_command_hdl(self):
        raise NotImplementedError

    #
    # Internal communications
    #

    def manage_proxy_socket(self):
        """
        Manage connection with proxy (channel) socket.
        @return:
        """
        channel_id, data = self.get_channel_data()

        if channel_id == COMMAND_CHANNEL:
            self.handle_proxy_cmd(data)

        elif channel_id in self.channels:
            relay_to_sock = self.channels[channel_id]

            log.debug('[channel {}] Got data to relay from remote side. '
                      'Data length: {}.'.format(channel_id, len(data)))

            self.relay(data, relay_to_sock)

        else:
            log.debug('Relay from socket {0} with channel {1} not possible. '
                      'Channel does not exist'.format(self.command_socket, channel_id))

    def handle_proxy_cmd(self, data):
        """
        Handle command from a proxy (command) socket
        @raise: RelayMainError, when unknown command received
        """
        cmd = b(data[0])
        log.debug('Received command from remote side: {0}'.format(cmd_names[cmd]))

        channel_id = struct.unpack('<H', data[1:3])[0]

        if cmd == CHANNEL_CLOSE_CMD:
            return self.close_channel_hdl(channel_id)

        elif cmd == CHANNEL_OPEN_CMD:
            return self.open_channel_hdl(data)

        elif cmd == FORWARD_CONNECTION_SUCCESS:
            return self.forward_connection_success_hdl(channel_id)

        elif cmd == FORWARD_CONNECTION_FAILURE:
            return self.forward_connection_failue_hdl(channel_id)

        elif cmd == CLOSE_RELAY:
            log.info('Got command to close relay. Closing socket and exiting.')
            self.shutdown()

        elif cmd == PING_CMD:
            self.ping_command_hdl()

        else:
            raise RelayMainError('Unknown command received: {}'.format(cmd.encode('hex')))

    def send_proxy_cmd(self, cmd, *args):
        """
        Send command to a proxy (command) socket
        @raise: RelayMainError
        """
        log.debug('Sending command to a remote side: {0}'.format(cmd_names[cmd]))

        if cmd in (CHANNEL_CLOSE_CMD, FORWARD_CONNECTION_SUCCESS, FORWARD_CONNECTION_FAILURE):
            cmd_buffer = cmd + struct.pack('<H', args[0])
        elif cmd == CHANNEL_OPEN_CMD:
            # for server only
            channel_id, ip, port = args
            cmd_buffer = cmd + struct.pack('<H', channel_id) + socket.inet_aton(ip) + struct.pack('<H', port)
        else:
            cmd_buffer = cmd

        tlv_header = struct.pack('<HH', COMMAND_CHANNEL, len(cmd_buffer))

        try:
            self.command_socket.send(tlv_header + cmd_buffer)
        except socket.error as err:
            (code, msg) = err.args
            raise RelayMainError('Socket error on sending command to remote side. Code {0}. Msg {1}'.format(code, msg))

    #
    # SOCKS client's methods
    #

    def close_socks_connection(self, sock):
        """
        @param sock: SOCKS client's socket
        """
        channel_id = self.id_by_socket[sock]
        log.debug('[channel {}] Closing SOCKS client connection'.format(channel_id))
        log.debug('[channel {}] Notifying remote side...'.format(channel_id))
        self.unset_channel(channel_id)
        self.input_connections.remove(sock)
        sock.close()
        self.send_proxy_cmd(CHANNEL_CLOSE_CMD, channel_id)

    def manage_socks_client_socket(self, sock):
        """
        Get data from a SOCKS client and send it to a proxy client.
        @param sock: SOCKS client's socket
        """

        if sock not in self.id_by_socket:
            log.debug('??? Channel corresponding to remote socket {0} already closed. '
                      'Closing forward socket'.format(sock))
            return

        channel_id = self.id_by_socket[sock]

        try:
            data = sock.recv(buffer_size)
        except socket.error as err:
            (code, msg) = err.args
            log.debug('[channel {}] Exception on reading socket {}.'
                      'Details: {}, {}'.format(channel_id, sock, errno.errorcode[code], msg))
            self.close_socks_connection(sock)
            return

        data_len = len(data)

        if data_len == 0:
            self.close_socks_connection(sock)
            return

        tlv_header = struct.pack('<HH', channel_id, data_len)
        log.debug('[channel {}] Got data to relay from the SOCKS client. Data length: {}'.format(channel_id, data_len))
        self.relay(tlv_header + data, self.command_socket)


def key_by_value(my_dict, value):
    for k, v in my_dict.items():
        if v == value:
            return k
    return None


class SocksRelay(Relay):

    def __init__(self, command_socket):
        super(SocksRelay, self).__init__(command_socket)
        self.establishing_dict = {}
        self.forward_socket = None
        self.data = None

        self.ping_thread = threading.Thread(target=self.ping_worker, name='Ping')
        self.ping_thread.start()

    #
    # Common methods
    #

    def ping_worker(self):
        while True:
            time.sleep(self.ping_delay)
            current_time = time.time()

            if self.remote_side_is_down:
                log.debug('Remote side down. Exiting ping worker')
                return

            if current_time - self.last_ping > self.relay_timeout:
                log.error('No response from remote side for {0} seconds. '
                          'Restarting relay...'.format(relay_timeout))
                self.command_socket.close()
                return

    def close_connection_with_server(self):
        self.command_socket.close()
        self.input_connections.remove(self.command_socket)

    #
    # Handle commands
    #

    def close_channel_hdl(self, channel_id):
        establishing_sock = key_by_value(self.establishing_dict, channel_id)
        if establishing_sock is not None:
            log.debug('[{0}] Closing establishing channel...'.format(channel_id))
            del self.establishing_dict[establishing_sock]
            return

        elif channel_id not in self.channels:
            log.debug('Channel {0} non existent'.format(channel_id))
            return

        sock_to_close = self.channels[channel_id]
        self.unset_channel(channel_id)
        log.debug('[{}] Closing channel...'.format(channel_id))
        sock_to_close.close()
        self.input_connections.remove(sock_to_close)

    def open_channel_hdl(self, data):
        channel_id, packed_ip, port = unpack('<HIH', data[1:9])
        ip = socket.inet_ntoa(data[3:7])
        log.debug('Got new channel request with id {0}. '
                  'Opening new forward connection to host {1} port {2}'.format(channel_id, ip, port))
        self.establish_forward_socket(channel_id, ip, port)

    def ping_command_hdl(self):
        self.last_ping = time.time()
        self.send_proxy_cmd(PING_CMD)

    #
    # SOCKS client's methods
    #

    def establish_forward_socket(self, channel_id, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(0)
            log.debug("[{}] Opening {}:{}".format(channel_id, host, port))
            sock.connect_ex((host, port))
        except socket.error as err:
            (code, msg) = err.args
            log.error("[{}] Caught exception socket.error: {}: {}".format(channel_id, code, msg))
            self.send_proxy_cmd(FORWARD_CONNECTION_FAILURE, channel_id)
            return

        log.debug('[{}] New pending forward connection: {}'.format(channel_id, sock))
        self.establishing_dict[sock] = channel_id

    #
    # ...
    #

    def run(self):
        ready_to_read = None
        ready_to_write = None

        while True:
            try:
                time.sleep(delay)
                log.debug('Active channels: {0}. Pending Channels {1}'.format(
                    ls(self.channels.keys()), ls(self.establishing_dict.values())))
                ready_to_read, ready_to_write, _ = \
                    select.select(self.input_connections, self.establishing_dict.keys(), [], 15)
            except KeyboardInterrupt:
                log.info('SIGINT received. Closing relay and exiting')
                self.send_proxy_cmd(CLOSE_RELAY)
                self.shutdown()
            except (select.error, socket.error) as err:
                (code, msg) = err.args
                log.error('Select error on select. Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
                self.shutdown()

            for sock in ready_to_write:
                channel_id = self.establishing_dict[sock]
                log.debug('[{0}] Establishing connection with channel id {0}'.format(channel_id))

                try:
                    sock.recv(0)
                except socket.error as err:
                    (code, err_msg) = err.args
                    if code == errno.ECONNREFUSED or code == errno.ETIMEDOUT:
                        if sock in ready_to_read:
                            ready_to_read.remove(sock)
                        del self.establishing_dict[sock]
                        self.send_proxy_cmd(FORWARD_CONNECTION_FAILURE, channel_id)
                        sock.close()
                        continue
                    elif code == errno.EAGAIN:
                        log.debug('Recv(0) return errno.EAGAIN for socket {0} on channel {1}. '
                                  'Connection established.'.format(sock, channel_id))
                    elif code == 10035:
                        log.debug('Recv(0) raised windows-specific exception 10035. Connection established.')
                    else:
                        raise

                log.info('Connection established on channel {0}'.format(channel_id))
                sock.setblocking(1)

                self.send_proxy_cmd(FORWARD_CONNECTION_SUCCESS, self.establishing_dict[sock])
                del self.establishing_dict[sock]
                self.input_connections.append(sock)
                self._set_channel(sock, channel_id)

            for selected_input_socket in ready_to_read:
                if selected_input_socket == self.command_socket:
                    try:
                        self.manage_proxy_socket()
                    except RelayMainError:
                        log.debug('Remote side closed socket')
                        self.close_sockets(self.input_connections)
                        return
                else:
                    try:
                        self.manage_socks_client_socket(selected_input_socket)
                    except RelayMainError as err:
                        log.debug(err)


def main():
    global log

    parser = optparse.OptionParser(description='Reverse socks client')
    parser.add_option('--server-ip', action="store", dest='server_ip')
    parser.add_option('--server-port', action="store", dest='server_port', default='9999')
    parser.add_option('--verbose', action="store_true", dest="verbose", default=False)
    parser.add_option('--logfile', action="store", dest="logfile", default=None)

    proxy_group = optparse.OptionGroup(parser, 'Ntlm Proxy authentication')

    proxy_group.add_option('--ntlm-proxy-ip', dest='ntlm_proxy_ip', default=None, action='store',
                           help='IP address of NTLM proxy')
    proxy_group.add_option('--ntlm-proxy-port', dest='ntlm_proxy_port', default=None, action='store',
                           help='Port of NTLM proxy')
    proxy_group.add_option('--username', dest='username', default='', action='store',
                           help='Username to authenticate with NTLM proxy')
    proxy_group.add_option('--domain', dest='domain', default='', action='store',
                           help='Domain to authenticate with NTLM proxy')
    proxy_group.add_option('--password', dest='password', default='', action='store',
                           help='Password to authenticate with NTLM proxy')
    proxy_group.add_option('--hashes', dest='hashes', default=None, action='store',
                           help='Hashes to authenticate with instead of password. Format - LMHASH:NTHASH')

    parser.add_option_group(proxy_group)

    cmd_options = parser.parse_args()[0]
    if cmd_options.server_ip is None:
        print('Server IP required')
        sys.exit()

    log = create_logger(__name__, True, cmd_options.verbose, cmd_options.logfile)

    log.info('============ Start proxy client ============')

    while True:
        log.info('Backconnecting to server {0} port {1}'.format(cmd_options.server_ip, cmd_options.server_port))
        backconnect_host = cmd_options.server_ip
        backconnect_port = int(cmd_options.server_port)
        bc_sock = None

        while True:
            try:
                bc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                bc_sock.connect((backconnect_host, backconnect_port))
                break
            except socket.error as err:
                (code, msg) = err.args
                log.error('Unable to connect to {0}:{1}. Caught socket error trying to establish '
                          'connection with RPIVOT server. Code {2}. Msg {3}. '
                          'Retrying...'.format(cmd_options.server_ip, cmd_options.server_port, code, msg))
                time.sleep(5)

        try:
            bc_sock.send(banner)
            banner_reponse_rcv = bc_sock.recv(4096)
            if banner_reponse_rcv != banner_response:
                log.error("Wrong banner response {0} from server. Retrying".format(repr(banner_reponse_rcv)))
                bc_sock.close()
                time.sleep(5)
                continue
        except socket.error as err:
            (code, msg) = err.args
            log.error('Caught socket error trying to establish connection with RPIVOT server. '
                      'Code {0}. Msg {1}'.format(code, msg))
            bc_sock.close()
            time.sleep(5)
            continue

        socks_relayer = SocksRelay(bc_sock)
        try:
            socks_relayer.run()
        except socket.error as err:
            (code, msg) = err.args
            log.error('Exception in socks_relayer.run(). '
                      'Errno: {0} Msg: {1}. Restarting ..'.format(errno.errorcode[code], msg))
            bc_sock.close()
            continue

        except KeyboardInterrupt:
            log.error("Ctrl C - Stopping server...")
            sys.exit(1)

        time.sleep(10)


if __name__ == '__main__':
    main()
