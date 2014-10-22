"""
setup:

apt-get install python3-pip
pip install IPy
python3 POODLEScanner.py 172.16.16.0/24

blackpiano0xicf@yahoo.com
"""
import socket, ssl, pprint, sys, IPy, argparse, multiprocessing

parser = argparse.ArgumentParser(description='Scan a netblock for SSLv3 enabled servers on port 443')
parser.add_argument('--port', '-p', nargs='*', default=["443"], help='port to connect to (default=443)')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--network', '-n', nargs='*', default=None, help='<network/mask>')
group.add_argument('--host', '-H', nargs='*', default=None, help='hostname')
parser.add_argument('--tls', '-t', action='store_true', default=False, help='check if SSLv3 is enabled and TLSv1 is not enabled\n otherwise just see if SSLv3 is enabled')
parser.add_argument('--parallel', '-P', action='store_true', default=False, help='Process netblocks in parallel')


def print_results(host, port, sslv3, tlsv1):
    if tlsv1 is None:
        print("{0}:{1} SSLv3 {2}".format(str(host), port, sslv3))
        return

    if sslv3 == "enabled" and tlsv1 != "enabled":
        print("{0}:{1} SSLv3 enabled and TLSv1 not enabled".format(str(host), port))
    else:
        print("{0}:{1} SSLv3={2} TLSv1={3}".format(str(host), port, sslv3, tlsv1))

def main():
    args = parser.parse_args()
    args = vars(args)

    ports = []
    for port in args["port"]:
        for port in port.split(','):
            ports.append(port)

    args["port"] = ports

    tlsv1 = None

    if args["host"] is not None:
        for host in args["host"]:
            for p in args["port"]:
                sslv3 = check_sslv3(host, p)
                if args["tls"] == True:
                    tlsv1 = check_tls(host, p)
                print_results(host, p, sslv3, tlsv1)
        return

    net = IPy.IPSet()

    for network in args["network"]:
        net.add(IPy.IP(network))

    if args["parallel"]:
        p = multiprocessing.Pool()
        q = multiprocessing.Queue()

        for ip in net:
            q.put((check_net, ip, args["port"], args["tls"]))

        while True:
            items = q.get()
            func = items[0]
            args = items[1:]
            p.apply_async(func, args)
            if q.empty():
                p.close()
                p.join()
                break
    else:
        for ip in net:
            check_net(ip, args["port"], args["tls"])

def check_net(ip, ports, tls):
    for x in ip:
        if ip.prefixlen() != 32 and (ip.broadcast() == x or ip.net() == x):
            continue
        for p in ports:
            tlsv1 = None
            sslv3 = check_sslv3(x, p)
            if tls == True:
                tlsv1 = check_tls(x, p)
            print_results(x, p, sslv3, tlsv1)

def check_tls(h, p):
    return check(h, p, ssl.PROTOCOL_TLSv1)

def check_sslv3(h, p):
    return check(h, p, ssl.PROTOCOL_SSLv3)

def check(h, p, ctx):
    context = ssl.SSLContext(ctx)
    context.verify_mode = ssl.CERT_NONE

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        ssl_sock = context.wrap_socket(s, server_hostname=str(h), do_handshake_on_connect=True)
        ssl_sock.connect((str(h), int(p)))
        ssl_sock.close()
        return "enabled"
    except Exception as e:
        return str(e)

if __name__ == "__main__":
        main()
