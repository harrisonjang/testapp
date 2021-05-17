
import sys
import os
# import argparse
# import json
import pexpect
# import imp
# import testList
# import testListFeature
import re
# from datetime import datetime
# from threading import Thread
# from time import sleep
# from collections import defaultdict
# import time
import pdb
# import sys

try:
    from pexpect import pxssh as pxssh
except:
    print("pxssh is not installed, if you want to run apptest on Hw and testScript method please install it")


from sshconnection import *


# 5 packets transmitted, 5 received, 0% packet loss, time 4104ms
# 5 packets transmitted, 0 received, +5 errors, 100% packet loss, time 4082ms

tx_str = r'.*(\d+) packets transmitted'
rx_str = r'.*(\d+) received'

tx_rx_str = r'.*(\d+) packets transmitted.*(\d+) received'
error_str = r'.*(\d+) errors'
packet_loss_and_time_str = r'.*(\d+).* packet loss, time (\d+)'


def compare_result(ping_result):

    parse_result = True
    tx_count = 0
    rx_count = 0
    err_count = 0
    packet_loss = 0
    run_time = 0
    
    # check result
    cmd_result_list = [i for i in re.split(r'[\r\n]', ping_result) if i.strip()]
    check_string = ' '.join(cmd_result_list[-6:])

    # tx / rx
    match_obj = re.match(tx_rx_str, check_string)
    if match_obj:            
        tx_count = int(match_obj.group(1))
        rx_count = int(match_obj.group(2))
    else:
        parse_result = False

    if parse_result:
        # error
        match_obj = re.match(error_str, check_string)
        if match_obj:
            err_count = int(match_obj.group(1))
        else:
            err_count = 0

    if parse_result:
        # packet loss, run time
        match_obj = re.match(packet_loss_and_time_str, check_string)
        if match_obj:            
            packet_loss = int(match_obj.group(1))
            run_time = int(match_obj.group(2))
        else:
            parse_result = False

    # test result for 1 test-case
    print('tx_count = {0}, rx_count = {1}, err_count = {2}, packet_loss = {3} %%, run_time = {4} ms'.format(tx_count, rx_count, err_count, packet_loss, run_time))

    return tx_count, rx_count, err_count, packet_loss, run_time, parse_result    


if __name__ == "__main__":

    argmnts = sys.argv[1:]

    dut_ip = argmnts[0]
    username = argmnts[1]
    passwd = argmnts[2]
    pingip = argmnts[3]
    pingcount = int(argmnts[4])
    testcount = int(argmnts[5])

    print('dut access info - ip {0}, user {1}, passwd {2}'.format(dut_ip, username, passwd))
    print('ping test info - ip {0}, ping count per test {1}, total ping test {2}'.format(pingip, pingcount, testcount))

    dut_connector = SshConnection(dut_ip, username, passwd)

    ping_test_cmd = "ping {0} -c {1}".format(pingip, pingcount)    
    pass_count = 0
    fail_count = 0       
    
    for test_no in range(testcount):
    
        print('')
        print('---------------------------------------')
        print('test-no {0}'.format(test_no))

        # do ping 
        ping_result = dut_connector.cmd(ping_test_cmd, allowPrint=False, debug=False)
        
        print('result ================================')
        print('{0}'.format(ping_result))
        print('=======================================')

        # 
        tx_count, rx_count, err_count, packet_loss, run_time, parse_result = compare_result(ping_result)
        if tx_count != pingcount or rx_count != pingcount or err_count != 0 or packet_loss != 0:
            fail_count = fail_count + 1
        else:           
            pass_count = pass_count + 1

    print('')
    print('---------------------------------------')            
    print('Total Test Count : {0}'.format(testcount))        
    print('Pass Count       : {0}'.format(pass_count))        
    print('Fail Count       : {0}'.format(fail_count))        
    print('---------------------------------------')            

