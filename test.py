# n = ipaddress.ip_network(u'10.10.20.2/24')
# first_host = next(n.hosts())

# ip = '1.0.0./8'
# import ipaddress
# net=ipaddress.ip_network(ip)
# first=str(net[1])
# last=str(net[-2])
# print(last)
# #
# # from ipaddress import IPv4Network
# #
# # test = IPv4Network('192.168.1.1/255.255.255.0').with_prefixlen
# # print(test)


#from netaddr import IPNetwork
#test2 = str(IPNetwork('1.2.3.4/255.255.255.0').cidr)
#print (test2)

import ipaddr

# matches = []
# for x in a:
#     if x in str and x not in matches:
#         matches.append(x)

# substrings = ["word","test"]
#
# strings = ["word string one",
#            "string two test",
#            "word and test",
#            "no matches in this string"]
#
# result = []
#
# for string in strings:
#     matches = []
#     for substring in substrings:
#         if substring in string:
#             matches.append(substring)
#     if matches:
#         result.append(matches)
#
# print(result)

#some_list = ['abc-123', 'def-456', 'ghi-789', 'abc-456']


# matching = [s for s in some_list if "abc" in s]
# print (matching)

# Read in the file
# with open('guru99.txt', 'r') as file :
#   filedata = file.read()
#
# # Replace the target string
# filedata = filedata.replace('A', 'replaced-a')
#
# # Write the file out again
# with open('guru99.txt', 'w') as file:
#   file.write(filedata

import fileinput

# textList = ["One", "Two", "Three", "Four", "Five"]
# #
# outF = open("myOutFile.txt", "w")
# for line in textList:
#     if 'write memory' in line:
#         f1.write("somedate1\n")  # Move f1.write(line) above, to write above instead
#         print('a')
#   # write line to output file
#     outF.writelines(line)
#     outF.write("\n")
# outF.close()

# line_to_replace = 17 #the line we want to remplace
# my_file = 'myOutFile.txt'
#
# with open(my_file, 'r') as file:
#     lines = file.readlines()
# #now we have an array of lines. If we want to edit the line 17...
#
# if len(lines) > int(line_to_replace):
#     lines[line_to_replace] = 'The text you want here'
#
# with open(my_file, 'w') as file:
#     file.writelines( lines )
#
#
# def line_prepender(myOutFile1, line):
#     with open(myOutFile1, 'r+') as f:
#         content = f.read()
#         f.seek(0, 0)
#         f.write(line.rstrip('\r\n') + '\n' + content)

#
# import os
# with open('input.txt', 'r') as f, open("new_file",'w') as f1:
#    for line in f:
#        if 'string' in line:
#           f1.write("somedate\n")  # Move f1.write(line) above, to write above instead
#        f1.write(line)
# os.remove('input.txt')  # For windows only
# os.rename("newfile", 'input.txt')  # Rename the new file

import os

# textList = ["One", "Two", "Three", "Four", "Five"]
# some_list = ['abc-123', 'def-456', 'ghi-789', 'abc-456']
#
#
# with open('myOutFile.txt', 'r') as f, open("new_file",'w') as f1:
#     for line in textList:
#        if 'Five' in line:
#           f1.write(line)  # Move f1.write(line) above, to write above instead
#           print('a')
#        f1.write(line)
#        f1.write("\n")
#        # f1.write("\n")

# with open('myOutFile.txt', 'r+') as f:
#    lines = f.readlines()
#    for i, line in enumerate(lines):
#        if 'test' in line:
#           lines.insert(i,"somedata2")  # inserts "somedata" above the current line
   # f.truncate(0)         # truncates the file
   # f.seek(0)             # moves the pointer to the start of the file
   # f.writelines(lines)   # write the new data to the file

# ip = ['1', '2', '3']
#
# with open('load_share_config.txt', 'r') as f:
#    lines = []
#    for line in f:
#        if line.startswith("test"):
#            split_line = line.split()
#            for ip_list in ip:
#                split_line.insert(split_line.index("test"), ip_list)
#                lines.append(' '.join(ip_list) + '\n')
#        else:
#            lines.append(line)
#
# with open('f2.txt', 'w') as f:
#    for line in lines:
#        f.write(line)
#


import os
with open(os.path.join('/path/to/Documents',completeName), "w") as file1:
    toFile = raw_input("Write what you want into the field")
    file1.write(toFile)