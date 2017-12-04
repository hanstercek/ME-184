#!/usr/bin/python

import sys
import difflib
from subprocess import Popen, PIPE
import time
import re
import socket
import os

# Username to associate with MAC address
if (len(sys.argv) < 2):
    print('Error: Please enter a username to pair:\n' + '       python3 buildDBName.py <username>')
    sys.exit()

username = sys.argv[1]
print("Target username: " + username)

## Baseline configuration
# Find base IP address
print ("Configuring...")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = (s.getsockname()[0])
s.close()

# Build prefix IP for nmap scan sweep
split_ip = re.split(r'(\.|/)', my_ip)
prefix_ip = ''.join(split_ip[0:5])
print(prefix_ip)

# Ping router to discover all devices
print  ("Establishing baseline ping...")
Popen(["nmap -sn " + prefix_ip + "/23"], stdout=PIPE, stderr=PIPE, shell=True).wait()

# Testing base reference
print ("Establishing baseline reference...")
base_pid = Popen(["arp", "-a"], stdout=PIPE)
base_ref = str(base_pid.communicate()[0]).strip().splitlines()

# Open database reference
mac_db = open('mac_db,json', 'a')
mac_db.write(',{\n')

mac = ""
counter = 0
# Break loop if MAC address found
while (counter < 99):
    print (str(counter) + " Checking for new members...\n")
    
    ##### SENSES #####
    # Read "arp -a" - solution from https://stackoverflow.com/questions/1750803
    new_pid = Popen(["arp", "-a"], stdout=PIPE)
    new_ref = str(new_pid.communicate()[0]).strip().splitlines()

    # Get additions - solution from http://stackoverflow.com/questions/19120489
    diff = difflib.unified_diff(base_ref, new_ref, fromfile='file1', tofile='file2', lineterm='', n=0)
    lines = list(diff)[2:]
    added = [line[1:] for line in lines if line[0] == '+']
    removed = [line[1:] for line in lines if line[0] == '-']

    ##### THINKS #####
    # Finds differences between scans
    i = 0
    new = [line for line in added if line not in removed]
    for line in new:
        # Include handling for multiple found addresses just in case!
        if (len(new) > 1 and i > 0): mac_db.write(',')

        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", line).groups()[0]
        print ("New MAC address found: " + mac + " associated with " + username)

        # Write MAC address to database
        mac_db.write('  "' + username + '": "' + mac + '"\n')
        counter = 99

    # Close database reference to update file
    # Reset base
    Popen(["nmap -sn " + prefix_ip + "/23"], stdout=PIPE, stderr=PIPE, shell=True).wait()
    base_ref = new_ref

    counter += 1

mac_db.write('}')
mac_db.close() 

##### ACTS #####
# Push to API
import requests
import json

url = 'https://academic-ni.cloud.thingworx.com/Thingworx/Things/maraudersData_ME184/Properties/*'
headers = { 'Content-Type': 'application/json', 'appKey': 'd0835923-7f86-490f-a542-1f4ae031a374' }

mac_db = open('mac_db.json')
parsed = mac_db.read()

payload = json.loads(parsed)
print(parsed)
 
response = requests.put(url, headers=headers, json=payload, verify=False)