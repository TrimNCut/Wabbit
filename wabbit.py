import socket
import argparse
import ipaddress
import re
import errno
import time
from concurrent.futures import ThreadPoolExecutor

startTime = time.monotonic()
version = "v1.1"

parser = argparse.ArgumentParser(description=f"Wabbit {version}, network and port scanning tool")
parser.add_argument("target", help="Target IP/URL \nThe URL e.g www.example.com\n or the IP Address e.g 127.0.0.1 of the target\nUse 'self' for scanning connected network")
parser.add_argument("-p", "--port", type=int, help="Specific port to scan e.g 43")
parser.add_argument("-o", "--output",default=False, action="store_true", help="Saves open ports in a text file")
parser.add_argument("-r", "--range", type=int, default=1024, help="Scans from 1 to the set range (max 65535)\n Default is 1024")
parser.add_argument("-O","--onlyopen", default=False, action="store_true", help="Ouput only open ports")
parser.add_argument("-t","--threading", default=False, action="store_true", help="Make use of threading, less stealthier")

args =parser.parse_args()
reg = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/?#]?.*", re.IGNORECASE)

target = args.target
#verify = False
res = ""
availablePorts = []

ip = ""

def verifyTarget(addr):
    global target, ip
    if args.target != "self":
        if reg.fullmatch(addr):
            if addr[len(addr)-1] == "/":
                host = addr.replace("https://", "").replace("http://", "").strip("/")
            else:
                host = addr.replace("https://", "").replace("http://", "")
            try:
                target = socket.gethostbyname(host)
            except socket.gaierror:
                print("[-] Could not resolve hostname")
                return
            except Exception as e:
                print(f"[-] Error occured: {e}")
            return
        else:
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                print("[-] Invalid IP Address")
                return
    else:
        v = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            v.connect(('8.8.8.8',80))
            ip = v.getsockname()[0]
            print(f"[+] Network address is {ip}")
            target = ip
        except Exception as e:
            print(f"[-] Error : {e}")
        finally:
            v.close()

    
def isIP(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def scan():
    global res
    if args.port != None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            con = s.connect_ex((target,args.port))
            if con == 0:
                if args.port not in availablePorts:
                    availablePorts.append(args.port)
                rec = s.recv(1024).decode().strip()
                res = f"OPEN -> {rec}"
            elif con == errno.ECONNREFUSED:
                res = "CLOSED"
            elif con == errno.ETIMEDOUT:
                res = "FILTERED -> TIMED OUT"
            elif con == errno.EHOSTUNREACH:
                res = "FILTERED -> HOST UNREACHABLE"
            elif con == errno.ENETUNREACH:
                res = "FILTERED -> NETWORK UNREACHABLE"
            else:
                res = f"FILTERED -> {con}"
            if args.onlyopen:
                if con == 0:
                    print(f"[+] {target}:{args.port} is {res}")
            else:
                print(f"[+] {target}:{args.port} is {res}")
        except socket.error as e:
            if con == 0:
                print(f"[-] {target}:{args.port} is OPEN | BANNER GRABBING ERROR -> {e}")
            else:
               if not args.onlyopen:
                    print(f"[-] {target}:{args.port} is {res} & {e}")
        finally:
            s.close()
            endTime = time.monotonic()
            elapsed = endTime-startTime
            print(f"\nScanned 1 port, found {len(availablePorts)} open")
            if len(availablePorts) >0:
                print(f"[+] Open ports : {sorted(availablePorts)}")
            print(f"[+] Scanned {args.range} ports in {elapsed:.4f}s")
    else:
        for i in range(args.range):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                con = s.connect_ex((target,i+1))
                if con == 0:
                    if i+1 not in availablePorts:
                        availablePorts.append(i+1)
                    rec = s.recv(1024).decode().strip()
                    res = f"OPEN -> {rec}"
                elif con == errno.ECONNREFUSED:
                    res = "CLOSED"
                elif con == errno.ETIMEDOUT:
                    res = "FILTERED -> TIMED OUT"
                elif con == errno.EHOSTUNREACH:
                    res = "FILTERED -> HOST UNREACHABLE"
                elif con == errno.ENETUNREACH:
                    res = "FILTERED -> NETWORK UNREACHABLE"
                else:
                    res = f"FILTERED -> {con}"
                if args.onlyopen:
                    if con == 0:
                        print(f"[+] {target}:{args.port} is {res}")
                    else:
                        print(f"[+] {target}:{args.port} is {res}")
            except socket.error as e:
                if con == 0:
                    print(f"[-] {target}:{i+1} is OPEN | BANNER GRABBING ERROR -> {e}")
                else:
                    if not args.onlyopen:
                        print(f"[-] {target}:{args.port} is {res} & {e}")
            finally:
                s.close()
        endTime = time.monotonic()
        elapsed = endTime-startTime
        print(f"\nScanned {args.range} ports, found {len(availablePorts)} open")
        if len(availablePorts) >0:
            print(f"[+] Open ports : {sorted(availablePorts)}")
        print(f"[+] Scanned {args.range} ports in {elapsed:.4f}s")

def singleScan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        con = s.connect_ex((target,port))
        if con == 0:
            if port not in availablePorts:
                availablePorts.append(port)
            rec = s.recv(1024).decode().strip()
            res = f"OPEN -> {rec}"
        elif con == errno.ECONNREFUSED:
            res = "CLOSED"
        elif con == errno.ETIMEDOUT:
            res = "FILTERED -> TIMED OUT"
        elif con == errno.EHOSTUNREACH:
            res = "FILTERED -> HOST UNREACHABLE"
        elif con == errno.ENETUNREACH:
            res = "FILTERED -> NETWORK UNREACHABLE"
        else:
            res = f"FILTERED -> {con}"
        if args.onlyopen:
            if con == 0:
                print(f"[+] {target}:{port} is {res}")
        else:
            print(f"[+] {target}:{port} is {res}")
    except socket.error as e:
        if con == 0:
            print(f"[-] {target}:{port} is OPEN | BANNER GRABBING ERROR -> {e}")
        else:
           if not args.onlyopen:
                print(f"[-] {target}:{port} is {res} & {e}")
    finally:
        s.close()    

print(f"==============  Wabbit {version}  ==============\n")

verifyTarget(target)
if isIP(target):
    if args.range > 65535:
        args.range = 65535
    if args.threading:
        with ThreadPoolExecutor(max_workers=100) as ex:
            for p in range(1, args.range+1):
                ex.submit(singleScan, p)
        endTime=time.monotonic()
        elapsed = endTime-startTime
        print(f"\n[+] Scanned {args.range} ports, found {len(availablePorts)} open")
        if len(availablePorts) >0:
            print(f"[+] Open ports : {sorted(availablePorts)}")
        print(f"[+] Scanned {args.range} ports in {elapsed:.4f}s")
    else:
        scan()
        endTime = time.monotonic()

if args.output:
    f = open("found_ports.txt",'w')
    f.write(f"======Wabbit {version}======\n")
    if len(availablePorts)>0:
        for i in range(len(availablePorts)):
            f.write(f"\n{target}:{availablePorts[i]}")
        f.write(f"\n\n[+] Scanned {args.range} ports, found {len(availablePorts)} open")
        f.write(f"\n[+] Scanned {args.range} ports in {elapsed:.4f}s")
    else:
        f.write("No open ports  :(")
    f.close()