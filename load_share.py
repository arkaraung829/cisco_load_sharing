
##Version 1.0##

import glob
import errno
import ipaddress
from netaddr import IPNetwork
import os

path_CE01 = 'config/CE01/*.txt'
path_CE02 = 'config/CE02/*.txt'
path_ES01 = 'config/ES01/*.txt'
#path_ES02 = 'config/ES02/*.txt'

files_CE01 = glob.glob(path_CE01)
files_CE02 = glob.glob(path_CE02)
files_ES01 = glob.glob(path_ES01)
#files_ES02 = glob.glob(path_ES02)

a = []
b = []

for name in files_CE01:
    try:
        with open(name) as f:
            for line in f:
                lines = f.readlines()
                #print(lines)
                lines = [item.replace("\n", "") for item in lines]
                lines = [item.replace("!", "") for item in lines]
                #print(lines)
                for i in range(len(lines)):
                    #print(i)
                    J = lines[i]
                    a.append(J)
                    #print(J)

                    if "standby 9" in lines[i]:
                        #print(i)
                        break
                #print(a)

                for k in reversed(range(len(a))):
                    #print(k)
                    L = a[k]
                    #print(L)
                    if "interface" in lines[k]:
                        lock1 = k
                        CE01_interface = lines[lock1]
                        print(CE01_interface)
                        break

                for k in reversed(range(len(a))):
                    M = a[k]
                    #print(M)
                    if "ip address" in lines[k]:
                        lock2 = k
                        standby_ip = lines[lock2]
                        standby_ip1 = standby_ip[12:]
                        standby_ip2 = standby_ip1.replace(' ', '/')
                        standby_ip3 = str(IPNetwork(standby_ip2).cidr)
                        standby_ip4 = ipaddress.ip_network(standby_ip3)
                        standby_ip_last = str(standby_ip4[-2])
                        #print(standby_ip2)
                        #print(standby_ip3)
                        print(standby_ip_last)
                        break

                for k in reversed(range(len(a))):
                    N = a[k]
                    #print(M)
                    if "standby 9 ip" in lines[k]:
                        lock3 = k
                        standby_ip = lines[lock3]
                        standby_ip1 = standby_ip[14:]
                        print(standby_ip1)
                        break

                for k in reversed(range(len(a))):
                    O = a[k]
                    #print(M)
                    if "hostname" in lines[k]:
                        lock4 = k
                        hostname = lines[lock4]
                        hostname1 = hostname[:-7]
                        hostname2 = hostname1[10:]
                        hostname3 = hostname2[:-4]
                        hostname4 = hostname2[-4:]
                        hostname5 = hostname3 + "-" + hostname4 + ".txt"
                        # print(hostname1)
                        # print(hostname2)
                        # print(hostname3)
                        # print(hostname4)
                        print(hostname5)
                        break

    except IOError as exc: #Not sure what error this is
        if exc.errno != errno.EISDIR:
            raise

for name in files_CE02:
    try:
        with open(name) as f:
            for line in f:
                lines = f.readlines()
                #print(lines)
                lines = [item.replace("\n", "") for item in lines]
                lines = [item.replace("!", "") for item in lines]
                #print(lines)
                for p in range(len(lines)):
                    #print(i)
                    Q = lines[p]
                    b.append(Q)
                    #print(Q)

                    if "standby 9" in lines[p]:
                        #print(i)
                        break
                #print(b)
                #
                for r in reversed(range(len(b))):
                    #print(r)
                    S = b[r]
                    #print(S)
                    if "interface" in lines[r]:
                        lock2 = r
                        CE02_interface = lines[lock2]
                        print(CE02_interface)
                        break

    except IOError as exc: #Not sure what error this is
        if exc.errno != errno.EISDIR:
            raise

for name in files_ES01:
    try:
        with open(name) as f_ES:
            for line_ES in f_ES:
                lines_ES = f_ES.readlines()
                # print(lines)
                lines = [item.replace("\n", "") for item in lines_ES]
                lines = [item.replace("!", "") for item in lines_ES]
                # print(lines)
                matching = [t for t in lines if "ip route" in t]
                matching1 = [t for t in matching if "ip route" in t]
                matching2 = [t for t in matching if standby_ip1 in t]
                matching3 = [item.replace(standby_ip1, standby_ip_last) for item in matching2]
                matching4 = [t.replace('ip route', 'no ip route') for t in matching3]
                #print(matching4)


    except IOError as exc: #Not sure what error this is
        if exc.errno != errno.EISDIR:
            raise


with open('load_share_config_template.txt', 'r') as f:
   lines = []
   for line in f:
       if line.startswith("mk1"):
           split_line = line.split()
           for ip_list in matching3:
               split_line.insert(split_line.index("mk1"), matching3)
               lines.append(''.join(ip_list))
               #print(ip_list)
       elif line.startswith("mk2"):
           split_line = line.split()
           for ip_list in matching4:
               split_line.insert(split_line.index("mk2"), matching4)
               lines.append(''.join(ip_list))
               #print(ip_list)
       else:
           lines.append(line)


with open(os.path.join('Output', hostname5), 'w')as f:
   for line in lines:
       f.write(line)
       #print(line)
#with open(os.path.join('/path/to/Documents',completeName), "w") as file1:


with open(os.path.join('Output', hostname5), 'r') as file :
  filedata = file.read()

# Replace the target string
filedata = filedata.replace('<AGENCY-SITE CODE>', hostname5)
filedata = filedata.replace('interface <CE01 LAN interface>', CE01_interface)
filedata = filedata.replace('interface <CE02 LAN interface>', CE02_interface)
filedata = filedata.replace('<Last Available IP address of VLAN9>', standby_ip_last)

# Write the file out again
with open(os.path.join('Output', hostname5), 'w') as file:
  file.write(filedata)

