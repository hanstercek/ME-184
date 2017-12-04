#!/usr/bin/python

# This file relies upon Terminal execution and user input to associate MAC addresses with a given username
import difflib
from subprocess import Popen, PIPE
import time
import re
import socket
import os

# Username to associate with MAC address
username = ""

## Baseline configuration
# Find base IP address
print ("Configuring...")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = (s.getsockname()[0])
s.close()

# Build 255 and 254 subnet masked IPs (easier than querying)
split_ip = re.split(r'(\.|/)', my_ip)
# Generate prefix ip for nmap scan
prefix_ip = ''.join(split_ip[0:5])
print(prefix_ip)

# Outdated ping scan
# split_ip[6] = "255"
# ip_255 = ''.join(split_ip)
# split_ip[6] = "254"
# ip_254 = ''.join(split_ip)
# print ("255 mask: " + ip_255 + "\n254 mask: " + ip_254 + "\n")

# Discover all devices on network using nmap
print ("Establishing baseline ping...")
Popen(["nmap -sn " + prefix_ip + "/23"], stdout=PIPE, stderr=PIPE, shell=True).wait()

# Read "arp -a" to generate base reference
base_pid = Popen(["arp", "-a"], stdout=PIPE)
base_ref = str(base_pid.communicate()[0]).strip().splitlines()

### Main Loop
counter = 0
while 1:
    print (str(counter) + " Checking for new members...\n")
    
    # Open database reference
    mac_db = open('mac_db.json', 'a')

    # Read "arp -a" to find new devices
    new_pid = Popen(["arp", "-a"], stdout=PIPE)
    new_ref = str(new_pid.communicate()[0]).strip().splitlines()

    # Get additions - solution from http://stackoverflow.com/questions/19120489
    diff = difflib.unified_diff(base_ref, new_ref, fromfile='file1', tofile='file2', lineterm='', n=0)
    lines = list(diff)[2:]
    added = [line[1:] for line in lines if line[0] == '+']
    removed = [line[1:] for line in lines if line[0] == '-']
    for line in added:
        if line not in removed:
            mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", line).groups()[0]
            print ("MAC address " + mac + " found. Enter username to asscoiate...")
            # Ask user for username query
            username = raw_input("Username to associate: ")
            print (mac + " associated with " + username)

            # Write MAC address to database
            mac_db.write(username + ' ' + mac + '\n')

    # Close database reference to update file
    mac_db.close()
    # Reset base
    Popen(["nmap -sn " + prefix_ip + "/23"], stdout=PIPE, stderr=PIPE, shell=True).wait()
    base_ref = new_ref

    counter += 1