import os
import sys
import json
import base64

import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from IPAddrScanner import IPAddrScanner
from Hslog import hs_log


def print_usage():
    print "Usage:"
    print "PassiveIpGetter.py <RPCPort> <ScanInterval-min> <NetSegmentToScan> <UserToFallback> <Daemon>"


class HostnameServer(HTTPServer):

    def __init__(self, scanner, *args, **kwargs):
        self.scanner = scanner
        scanner.run_in_thread()
        HTTPServer.__init__(self, *args, **kwargs)

    def finish_request(self, request, client_address):
        request.settimeout(2)
        # "super" can not be used because BaseServer is not created from object
        BaseHTTPServer.HTTPServer.finish_request(self, request, client_address)

    def handle_scan_now_command(self):
        self.scanner.do_update_now()

    def auth(self, user, passwd):
        if user == "fiblab" and passwd == "fib10202":
            return True

        return False

    @staticmethod
    def json_pretty_print(obj):
        return json.dumps(obj, sort_keys=True, indent=4, separators=(',', ': '))

    def get_status_json(self):
        return self.json_pretty_print(self.scanner.get_rpc_query_status_result())

    def get_ip_of_mac_json(self, mac_addr):
        return self.json_pretty_print(self.scanner.get_rpc_query_addr_result(mac_addr))

    def get_arp_table_json(self):
        return self.json_pretty_print(self.scanner.get_rpc_query_arp_list())

    def get_ip_for_mac(self, ip_addr):
        return self.json_pretty_print(self.scanner.get_rpc_query_ip_for_mac(ip_addr))

    def do_wol(self, mac_addr):
        return self.json_pretty_print(self.scanner.rpc_wol_mac(mac_addr))


class HostnameRequestHandler(BaseHTTPRequestHandler):

    def write_common_header(self, response_code=200, content_type=None, other_fields=None):
        self.protocol_version = 'HTTP/1.1'
        self.send_response(response_code)
        if content_type is not None:
            self.send_header('Content-Type', content_type)

        if isinstance(other_fields, dict):
            for k, v in other_fields.items():
                self.send_header(k, v)

        self.end_headers()

    def auth(self, code_succeed=200, content_type_succeed=None, headers_succeed=None):
        if "authorization" not in self.headers:
            self.write_common_header(401, other_fields={'WWW-Authenticate': 'Basic realm="Test"'})
            return False

        challenge = self.headers["authorization"]
        if not challenge.startswith("Basic "):
            self.send_error(401)
            return False

        b64up = challenge[len("Basic "):]
        try:
            auth = base64.b64decode(b64up)
            user, passwd = auth.split(':')
            if self.server.auth(user, passwd):
                self.write_common_header(code_succeed, content_type=content_type_succeed,
                                         other_fields=headers_succeed)
                return True
            else:
                self.send_error(401)
                return False

        except:
            self.send_error(401)
            return False

    def do_GET(self):
        # print self.path
        path_components = self.path.split("/")
        if len(path_components) <= 1 or len(path_components) >= 3:
            self.write_common_header(404)
        else:
            p2 = path_components[1]
            if p2.startswith('?mac='):
                mac_addr = p2.replace("?mac=", "")
                self.write_common_header(content_type="application/json")
                self.wfile.write(self.server.get_ip_of_mac_json(mac_addr))
            elif p2 == "state.look":
                # if self.auth(code_succeed=200, content_type_succeed="application/json"):
                #    self.wfile.write(self.server.get_status_json())
                self.write_common_header(content_type="application/json")
                self.wfile.write(self.server.get_status_json())
            elif p2 == "arp_table.look":
                if self.auth(code_succeed=200, content_type_succeed="application/json"):
                    self.wfile.write(self.server.get_arp_table_json())
            elif p2 == "scan_now.do":
                if self.auth(code_succeed=200, content_type_succeed="application/json"):
                    self.server.handle_scan_now_command()
                    self.wfile.write(json.dumps({"result": "OK"}))
            elif p2.startswith("wol.do?mac="):
                mac_addr = p2.replace("wol.do?mac=", "")
                self.write_common_header(content_type="application/json")
                self.wfile.write(self.server.do_wol(mac_addr))
            elif p2.startswith("?ip="):
                ip_addr = p2.replace("?ip=")
                self.write_common_header(content_type="application/json")
                self.wfile.write(self.server.get_ip_for_mac(ip_addr))
            else:
                self.send_error(404)


def deamon():
    if os.fork() > 0:
        sys.exit(0)

    os.setsid()
    os.chdir("/")
    os.umask(0)

    if os.fork() > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()

    si = file('/dev/null', 'r')
    so = file('/dev/null', 'a+')
    serr = file('/dev/null', 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(serr.fileno(), sys.stderr.fileno())

if len(sys.argv) != 6:
    print_usage()
    exit(1)

rpcport = int(sys.argv[1])
interval = int(sys.argv[2])
net_seg = sys.argv[3]
fallback_user = sys.argv[4]
daemonlize = sys.argv[5]
if daemonlize.upper() == "TRUE" or daemonlize.upper() == "YES" or daemonlize == "1":
    deamon()

scanner = IPAddrScanner(interval=interval, net_seg=net_seg, fallback_user=fallback_user)
hostServer = HostnameServer(scanner, ('', rpcport), HostnameRequestHandler)
hs_log("Starting PassiveIpGetter...")
try:
    hostServer.serve_forever()
except:
    hs_log("PassiveIpGetter daemon unexceptly stopped.")
    sys.exit(3)
