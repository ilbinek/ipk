#!/usr/bin/env python3

# Tested on Python 3.9.2 and on Merlin with python3
# Execution:
#   python3 filget.py -n <adress> -f <fsp://nameserver/pathtofile>
#   ./filget -n <address> -f <fsp://nameserver/pathtofile>
# use -s (--show) as a command line to show what file is currently being downloaded

'''
    Author: Sotirios Pupakis
    Login:  xpupak01 
'''

import argparse
from urllib.parse import urlparse
import socket
import re
from pathlib import Path
import sys

def getaddress(addressPort, nameserver):
    msg = "WHEREIS {}".format(nameserver)
    bytesToSend = str.encode(msg)
    bufferSize = 2048
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM) as client:
        try:
            client.settimeout(10)
            client.sendto(bytesToSend, addressPort)
            msgFromServer = client.recvfrom(bufferSize)
            addressToParse = msgFromServer[0].decode()
            if re.match(r"OK.*", addressToParse):
                return addressToParse[3:].split(":")
            else:
                print("Did not get OK return from WHEREIS")
                sys.exit(2)
        except socket.timeout:
            print("WHEREIS timed out")
            sys.exit(1)
        except socket.error:
            print("Connection refused")
            sys.exit(1)
        except Exception as msg:
            print("An exception occured, please check the logs and report the problem back to us")
            print(msg)
            sys.exit(1)

    return addressToParse

def getFile(addressPort, file, nameserver, agent):
    # Check if I need to create a directory to store it in
    if "/" in file:
        # Got to create the dir
        spl = file.split("/")
        d = ""
        for i in range(len(spl)-1):
            d += spl[i] + "/"
        Path(d).mkdir(parents=True, exist_ok=True)


    msg = "GET {} FSP/1.0\r\nHostname: {}\r\nAgent: {}\r\n\r\n".format(file, nameserver, agent)
    bytesToSend = str.encode(msg)
    bufferSize = 2048
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as client:
        try:
            # Send message to the server
            client.settimeout(10)
            client.connect(addressPort)
            client.sendall(bytesToSend)

            # Get the header
            data = client.recv(bufferSize)

            # Check header
            if not re.match(r"FSP\/1\.0 Success.*", data[:15].decode()):
                print("File not found or other FSP Error:")
                print(data)
                sys.exit(4)

            # Remove header
            counter = 0
            while True:
                if data[:counter].decode().endswith("\r\n\r\n"):
                    editedData = data[counter:]
                    break
                counter += 1
            
            # Read from socket and do magic - stram it into file
            f = open(file, "wb")
            f.write(editedData)
            while True:
                data = client.recv(bufferSize)
                if len(data) == 0:
                    break
                f.write(data)
            f.flush()
            f.close()
        except socket.timeout:
            print("GET timed out")
            sys.exit(3)
        except socket.error:
            print("Connection refused")
            sys.exit(3)
        except Exception as msg:
            print("An exception occured, please check the logs and report the problem back to us")
            print(msg)
            sys.exit(3)

def getIndex(addressPort, nameserver, agent):
    msg = "GET index FSP/1.0\r\nHostname: {}\r\nAgent: {}\r\n\r\n".format(nameserver, agent)
    bytesToSend = str.encode(msg)
    bufferSize = 2048
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as client:
        try:
            # Send message to the server
            client.settimeout(10)
            client.connect(addressPort)
            client.sendall(bytesToSend)

            # Get the header
            data = client.recv(bufferSize).decode()
            # Parse header
            if not re.match(r"FSP\/1\.0 Success.*", data):
                print("File not found or other FSP Error:")
                print(data)
                sys.exit(4)

            splitted = data.split()
            f = open("index", "w")
            ret = splitted[3:]
            if len(splitted) != 3:
                # header has data in it
                for i in range(3, len(splitted)):
                    f.write(splitted[i] + "\r\n")

            while True:
                data = client.recv(bufferSize).decode()
                ret = ret + data.split()
                if len(data) == 0:
                    break
                f.write(data)
            
            f.flush()
            f.close()
            return ret
            
        except socket.timeout:
            print("GET timed out")
            sys.exit(3)
        except socket.error:
            print("Connection refused")
            sys.exit(3)
        except Exception as msg:
            print("An exception occured, please check the logs and report the problem back to us")
            print(msg)
            sys.exit(3)


def main():

    agent = "xpupak01"

    # Parsing of comand line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--nameserver", help="The nameserver", required=True)
    parser.add_argument("-f", "--file", help="File that will be downloaded", required=True)
    parser.add_argument("-s", "--show", help="Prints file that is being currently downloaded", action="store_true")
    args = parser.parse_args()

    # Get address and port of the server
    # -n checks
    if not re.match(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(102[0-3]|10[0-1]\d|[1-9][0-9]{0,4}|0)", args.nameserver):
        print("-n not  matching ip:port")
        sys.exit(45)
    address, port = args.nameserver.split(":")
    port = int(port)

    # Get the fileserver
    parsed = urlparse(args.file)
    # -f checks
    if parsed[0] != "fsp":
        print("Scheme not FSP")
        sys.exit(46)
    if parsed[1] == "":
        print("Netloc empty")
        sys.exit(47)
    if parsed[2] == "/" or parsed[2] == "":
        print("Path empty")
        sys.exit(48)
    address, port = getaddress((address, port), parsed[1])
    port = int(port)

    # Find out what to download
    path = parsed[2][1:]
    if path == "index":
        getIndex((address, port), parsed[1], agent)
    elif path == "*":
        # Some magic with index
        index = getIndex((address, port), parsed[1], agent)
        for f in index:
            if args.show:
                print(f"Downloading: {f}")
            getFile((address, port), f, parsed[1], agent)
    else:
        getFile((address, port), path, parsed[1], agent)






if __name__ == "__main__":
    main()

# GET <file> FSP/1.0\r\nHostname: <hostname>\r\nAgent: xpupak01\r\n\r\n