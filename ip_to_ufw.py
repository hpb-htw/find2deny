#!/usr/bin/python3

import ipaddress



'''
reads file IP2LOCATION-LITE-DB1.CSV and convert ip_from -> up_to in 
ufw Command to block the IP Range from ip_from to ip_to

Usage: 2 Steps

In local laptop:

python3 ip_to_ufw.py > block-ip.sh
scp block-ip.sh <remote>:~/

In remote Server:

cd ~
sudo ./block-ip.sh
'''

rule_count = 0

def do_job():
    filepath = 'IP2LOCATION-LITE-DB1.CSV' #'one-line.csv'
    with open(filepath) as fp:
        line = fp.readline()
        while line:
            lines = line.split(",")
            country_code = lines[2]
            if country_code == '"CN"': # Block all IPs from CN
                from_ip = lines[0]
                to_ip = lines[1]
                numeric_str_to_range(from_ip, to_ip, print_range)
            line = fp.readline()



def numeric_str_to_range(bigint_ip_first, bigint_ip_last, range_process):
    global rule_count
    ip_first = ipaddress.ip_address( int( bigint_ip_first.replace('"','') ) )
    ip_last =  ipaddress.ip_address( int( bigint_ip_last.replace('"','') ) )
    for ip in ipaddress.summarize_address_range( ip_first, ip_last ):
        rule_count += 1
        range_process(ip, rule_count)


def print_range(ip_range, rule_count):
    print( "echo [{1}] 'block {0}';  ufw deny from {0} to any".format(ip_range,rule_count) )


do_job()
