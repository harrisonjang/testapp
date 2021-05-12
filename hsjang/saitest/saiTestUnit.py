# coding=utf-8

import sys
import os
import pexpect
# import imp
# import testList
# import testListFeature
import re
from datetime import datetime
from threading import Thread
from time import sleep
from collections import defaultdict
import time
import sys

try:
   import scapy.all as t_scapy
except IOError:
   print("Caught Exception IOError")

try:
    from pexpect import pxssh as pxssh
except:
    print("pxssh is not installed, if you want to run apptest on Hw and testScript method please install it")

from saiobjid import *

winsize_row = 128
winsize_col = 256

class SshConnection(object):
    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        try:
            self.ssh_conn = self.ssh_conn(self.hostname, self.username, self.password)
            self.ssh_conn.PROMPT = "[#>$]"
            self.ssh_conn.timeout = 5000
        except Exception as err:
            print("Connection to %s failed" % self.hostname)
            sys.exit()

    # To establish connection using ssh
    def ssh_conn(self, hostname, username, password):
        try:
            print("Connecting to", hostname)
            self.ssh = pxssh.pxssh()
            print(hostname, username)
            self.ssh.login(hostname, username, password, original_prompt="[#>$]", login_timeout=5000, auto_prompt_reset=False)
            print("Connected")
        except pxssh.ExceptionPxssh as error:
            print("Login failed")
            print(str(error))
            self.ssh = False
            sys.exit()

        self.ssh.setwinsize(winsize_row, winsize_col)     
        return self.ssh

    # To apply command on ssh prompt, which is connected using ssh_conn methode
    def cmd(self, command, allowPrint=True, sleep=False, killApptest=False):
        prompt_repeat = 0
        buff_pos = 0
        retries = self.ssh_conn.timeout
        tmpbuf = ''
        self.ssh_conn.buffer = ''
        self.ssh_conn.sendline(command)
        time.sleep(0.1)
        if command.find("exit") != -1:
            return self.ssh_conn.before
        if sleep:
            time.sleep(20)
        if not self.ssh_conn.prompt(timeout=1):
            while self.ssh_conn.prompt(timeout=1) is not True and prompt_repeat < retries:
                if (self.ssh_conn.buffer != None):
                    if allowPrint:
                        if len(self.ssh_conn.buffer) > buff_pos:
                            print("{0}".format(self.ssh_conn.buffer[buff_pos:]))
                            buff_pos = len(self.ssh_conn.buffer)
                # self.ssh_conn.buffer = ''
                prompt_repeat += 1
            if prompt_repeat == retries:
                print("Failed to detect prompt %s for %s times" % (self.ssh_conn.PROMPT, retries))
                print(tmpbuf)
                if killApptest:
                    print("=" * 100)
                    print(
                        "Failed to detect prompt %s for %s times for %s cmd" % (self.ssh_conn.PROMPT, retries, command))
                    print("=" * 100)
                    cleanup()
                    sys.exit()
                return False
            else:
                tmpbuf = self.ssh_conn.before
                if allowPrint:
                    if len(tmpbuf) > buff_pos:
                        print("{0}".format(tmpbuf[buff_pos:]))

                return tmpbuf
        else:
            tmpbuf = self.ssh_conn.before
            if allowPrint:
               print('{0}'.format(tmpbuf))
            return tmpbuf

    def set_prompt_for_expect(self, prompt):
        self.ssh_conn.PROMPT = prompt

    def close(self):
        try:
            self.ssh_conn.close()
            print("connection to %s closed" % self.hostname)
        except Exception as err:
            print(err)
            sys.exit()


def comparestr(output, expect1):

    #print "Comparing strings : " + "output = " + output + "expected = " + expect1
    p = output
    p = p.replace(' ', '')
    p = "".join(p.split())
    q = expect1
    q = q.replace(' ', '')
    q = "".join(q.split())
    if p.find(q) != -1:
        return True
    else:
        return False


def parse_mac_counters(cmd_result, debug=True):

    rx_match = [r'.*RxUC\s*(0x[\da-fA-F]+)', r'.*RxMC\s*(0x[\da-fA-F]+)', r'.*RxBC\s*(0x[\da-fA-F]+)']
    tx_match = [r'.*TxUC\s*(0x[\da-fA-F]+)', r'.*TxMC\s*(0x[\da-fA-F]+)', r'.*TxBC\s*(0x[\da-fA-F]+)']

    if isinstance(cmd_result, list):
        cmd_result = ' '.join(cmd_result)

    rx_res = [0, 0, 0]
    for i in range(len(rx_match)):
        match_obj = re.match(rx_match[i], cmd_result)
        if match_obj:
            rx_res[i] = int(match_obj.group(1), 16)

    if debug:
        print('rx_res : {0}'.format(rx_res))

    tx_res = [0, 0, 0]
    for i in range(len(tx_match)):
        match_obj = re.match(tx_match[i], cmd_result)
        if match_obj:
            tx_res[i] = int(match_obj.group(1), 16)

    if debug:
        print('tx_res : {0}'.format(tx_res))

    return rx_res, tx_res


def process_sai_objname_in_cmd(cmd):
    srch_obj = re.search(r'\&([_a-zA-Z]+)(\d+)', cmd)
    if not srch_obj:
        return cmd, False

    _cmd = cmd.split(' ')        
    for i in range(len(_cmd)):
        match_obj = re.match(r'^\&([_a-zA-Z]+)(\d+)', _cmd[i])
        if match_obj:
            name = (match_obj.group(1)).lower()
            index = int(match_obj.group(2))
            if name in sai_obj_name_tbl:
                _cmd[i] = '{0}'.format((sai_obj_name_tbl[name])[1] + index)   
    return ' '.join(_cmd), True   


def find_obj_info(obj_id): 
    if isinstance(obj_id, str):
        obj_id = int(obj_id)

    obj_idx = obj_id >> 48 
    if obj_idx > 0 and obj_idx <= 0x005d:
        obj_info = sai_obj_name_list[obj_idx]
        obj_info = "{0} ({1}{2}, 0x{3:016x})".format(obj_info[1], obj_info[0], (obj_id - obj_info[2]) & 0x000FFFFF, obj_id) 
        return obj_info
    else:
        return ' '             


class SaiTestUnit(object):
    def __init__(self, config_info):

        self.ip = config_info['ip']
        self.port = config_info['port']
        self.user = config_info['user']
        self.passwd = config_info['passwd']
        self.run_app = config_info['run_app']
        self.path_xdk = config_info['path_xdk']
        self.ssh_intf = None
        self.test_port_list = config_info['testportlist']
        self.telnet_intf = None
        self.telnet_prompt = "Console#"        

        self.dev_type = "Aldrin3-XL" if config_info['devtype'] == "ac5p" else "Falcon"
        self.enable_log = True if config_info['log'] in ['True', 'Yes', 'Enable', '1'] else False
        self.debug = True if config_info['debug'] in ['True', 'Yes', 'Enable', '1'] else False

        self.cpu_rx_count = 0
        
        self.var_dict = {}
        self.acl_counter_check = False
        self.acl_counter_info = {}
        self.acl_counter = None

        self.packet_count = 0
        self.ingress_port = None
        self.egress_port = None

        self.last_cmd_result = None
        self.expected_count = None
        self.expected_data = None

    def ssh_connect(self):
        self.ssh_intf = SshConnection(self.ip, self.user, self.passwd)

    def ssh_set_prompt(self, prompt):
        self.ssh_intf.set_prompt_for_expect(prompt)        

    def _cmd_(self, command, allow_print=True, sleep=False, kill_apptest=False):    

        cmd_result = self.ssh_intf.cmd(command, allow_print, sleep, kill_apptest)
        match_obj = re.match(r'sai_remove\w+\s+.*\$(\w+)', command)
        if match_obj:
            var_key = match_obj.group(1)
            if var_key in self.var_dict:
                del self.var_dict[var_key]
            if var_key in self.acl_counter_info:
                del self.acl_counter_info[var_key]
        else:
            _cmd_result = ' '.join((re.split(r'[\r\n]', cmd_result))[1:])
            if cmd_result.find("Invalid") == -1:                    
                # var_dict and acl_counter_info            
                self.add_var_info(command, _cmd_result)
                self.update_acl_counter_info(command)

        return cmd_result

    def cmd(self, command, allow_print=True, sleep=False, kill_apptest=False):
        _command, modified = process_sai_objname_in_cmd(command)
        if modified:
            print('[CMD] {0}'.format(command))
        return self._cmd_(_command, allow_print, sleep, kill_apptest)

    def cmd2(self, command, allow_print=True, sleep=False, kill_apptest=False):
        cmd_result = self.cmd(command, allow_print, sleep, kill_apptest)
        cmd_result_list = [i for i in re.split(r'[\r\n]', cmd_result) if i.strip()]
        return cmd_result_list

    def cmd3(self, command, allow_print=True, sleep=False, kill_apptest=False):
        cmd_result = self.cmd(command, allow_print, sleep, kill_apptest)
        cmd_result_list = [i for i in re.split(r'[\r\n]', cmd_result) if i.strip()]
        return ' '.join(cmd_result_list)

    def command(self, command, loop_var, allow_print=True, sleep=False, kill_apptest=False):
        
        modified_1 = False
        if command.find('$counter') != -1 and loop_var != 'None':    
            command = command.replace("$counter", '{0}'.format(loop_var))
            modified_1 = True

        _command, modified_2 = process_sai_objname_in_cmd(command)
        if modified_1 or modified_2:
            print('[CMD] {0}'.format(command))
            
        cmd_result = self._cmd_(_command, allow_print, sleep, kill_apptest)
        if self.enable_log:
            print('{0}'.format(cmd_result))

        cmd_result = ' '.join((re.split(r'[\r\n]', cmd_result))[1:])
        if cmd_result.find("Invalid") != -1:                    
            print("invalid input : {0} - {1}".format(command, cmd_result))
            rvalue = False
        else:               
            rvalue = True

        self.last_cmd_result = cmd_result
        return rvalue

    def set_path_xps_mac(self, enable_log=False):
        self.ssh_intf.cmd('home', enable_log)
        self.ssh_intf.cmd('xps', enable_log)
        self.ssh_intf.cmd('mac', enable_log)

    def set_path_xps_packetdrv(self, enable_log=False):
        self.ssh_intf.cmd('home', enable_log)
        self.ssh_intf.cmd('xps', enable_log)
        self.ssh_intf.cmd('packetdrv', enable_log)

    def set_path_xps_port(self, enable_log=False):
        self.ssh_intf.cmd('home', enable_log)
        self.ssh_intf.cmd('xps', enable_log)
        self.ssh_intf.cmd('port', enable_log)

    def set_path_sai_switch(self, enable_log=False):
        self.ssh_intf.cmd('home', enable_log)
        self.ssh_intf.cmd('sai', enable_log)
        self.ssh_intf.cmd('switch', enable_log)

    def set_path_sai_acl(self, enable_log=False):
        self.ssh_intf.cmd('home', enable_log)
        self.ssh_intf.cmd('sai', enable_log)
        self.ssh_intf.cmd('acl', enable_log)

    def set_path_sai_port(self, enable_log=False):
        self.ssh_intf.cmd('home', enable_log)
        self.ssh_intf.cmd('sai', enable_log)
        self.ssh_intf.cmd('port', enable_log)

    def set_log_level(self, log_level=2, enable_log=False):
        self.ssh_intf.cmd('home', enable_log)
        self.ssh_intf.cmd('log', enable_log)
        self.ssh_intf.cmd('set_log_level {0}'.format(log_level), enable_log)

    def get_cpu_rx_counter(self, enable_log=False):
        self.set_path_xps_packetdrv()
        cmd_result = self.cmd3("packet_driver_get_pkt_rx_tx_statistics 0", enable_log)
        match_obj = re.match(r'.*Rx Counters\s*\=\s*(\d+)', cmd_result)
        rx_val = int(match_obj.group(1)) if match_obj else 0
        return rx_val

    def clear_cpu_stat(self, enable_log=False):
        self.set_path_xps_packetdrv()
        cmd = 'packet_driver_get_pkt_rx_tx_statistics 0'
        self.cmd(cmd, enable_log)

    def get_mac_counters(self, port, enable_log=False):
        self.set_path_xps_mac(enable_log)
        cmd = 'mac_get_counter_stats 0 ' + port         # dev 0 / port
        cmd_result_list = self.cmd2(cmd, enable_log)
        return ' '.join(cmd_result_list)

    def clear_mac_counters(self, port, enable_log=False):
        self.set_path_xps_mac()
        cmd = 'mac_stat_counter_reset 0 {0}'.format(port)
        self.cmd(cmd, enable_log)

    def get_first_port(self, enable_log=False):
        self.set_path_xps_port()
        cmd_result = self.cmd3('port_get_first', enable_log)
        match_obj = re.match(r'.*\=\s*(\d+)', cmd_result)
        port = int(match_obj.group(1)) if match_obj else 0
        return port

    def get_next_port(self, port, enable_log=False):
        self.set_path_xps_port()
        cmd = 'port_get_next {0}'.format(port)
        cmd_result = self.cmd3(cmd, enable_log)
        match_obj = re.match(r'.*\=\s*(\d+)', cmd_result)
        port = int(match_obj.group(1)) if match_obj else 0
        return port

    def get_max_port(self, enable_log=False):
        self.set_path_xps_port()
        cmd = 'port_get_max_num 0'
        cmd_result = self.cmd3(cmd, enable_log)
        match_obj = re.match(r'.*\=\s*(\d+)', cmd_result)
        port = int(match_obj.group(1)) if match_obj else 0
        return port

    def get_sai_port_list(self, max_ports, enable_log=False):
        self.set_path_sai_switch()
        command = 'sai_get_switch_attribute 9288674231451648 SAI_SWITCH_ATTR_PORT_LIST {0}'.format(max_ports)
        port_list = self.cmd3(command, enable_log)
        port_list = port_list.split()
        return port_list[-int(max_ports):]

    def set_port_enable(self, port, enable_log=False):
        self.set_path_xps_mac()
        port_enable = 'mac_port_enable 0 {0} 1'.format(port)
        self.cmd(port_enable, enable_log)

    def init_test_case_loop(self, mod):
        # loop
        test_list = []
        if 'counter' in mod.tcParams:        
            if mod.tcParams['counter'] == 'max_ports':
            
                counter = self.get_max_port()
                if self.dev_type == 'Falcon':
                    counter = counter - 1
                port = self.get_first_port()                
                for k in range(counter):
                    test_list.append(port)
                    port = self.test_unit.get_next_port(port)

            elif mod.tcParams['counter'] == 'sai_ports':
                counter = self.get_max_port()
                test_list = self.get_sai_port_list(counter)
            else:
                counter = mod.tcParams['counter']
                test_list = range(int(counter))
        else:
            test_list.append('None')

        return test_list

    def init_test_data(self, mod):

        self.packet_count = mod.tcParams['packetCount'] if 'packetCount' in mod.tcParams else 1    
        self.ingress_port = mod.tcParams['ingressPort'] if 'ingressPort' in mod.tcParams else None
        self.egress_port = mod.tcParams['egressPort'] if 'egressPort' in mod.tcParams else None
        self.expected_count = mod.tcParams['count'] if 'count' in mod.tcParams else None
        self.expected_data = mod.expectedData if hasattr(mod, 'expectedData') else None

        if 'acl_counter' in mod.tcParams:
            self.acl_counter = mod.tcParams['acl_counter']  
            for acl_count_id in self.acl_counter:
                if acl_count_id in self.var_dict:
                    del self.var_dict[acl_count_id]
                if acl_count_id in self.acl_counter_info:
                    del self.acl_counter_info[acl_count_id]
        else:
            self.acl_counter = None

    def ac5p_workround(self, enable_log=False):
        self.set_path_sai_port()
        for port in self.test_port_list:
            cmd = "sai_set_port_attribute {0} SAI_PORT_ATTR_ADMIN_STATE 0".format((0x0001 << 48) + port)
            self.cmd(cmd, enable_log)
            cmd = "sai_set_port_attribute {0} SAI_PORT_ATTR_ADMIN_STATE 1".format((0x0001 << 48) + port)
            self.cmd(cmd, enable_log)

    def update_acl_counter_info(self, cmd):
        if self.acl_counter and cmd.find('sai_create_acl_counter') != -1:
            for counter_name in self.acl_counter:
                if cmd.find(counter_name) != -1:                    
                    self.acl_counter_info[counter_name] = (self.var_dict[counter_name][0], 0) if counter_name in self.var_dict else (0, 0)
                    if self.debug:
                        print('[Debug] =========================================================================================================')              
                        print('acl_counter_info[{0}] = {1}'.format(counter_name, self.var_dict[counter_name][0]))              
                        print('=================================================================================================================')              

    def add_var_info(self, cmd, cmd_result):
        if '>' in cmd:
            match_obj = re.match(r'.*\>\s*(\w+)\s*', cmd)
            if match_obj:
                var_key = match_obj.group(1)        
            else:
                return               
            
            match_obj = re.match(r'.*\s+(\d+)', cmd_result)
            if match_obj:            
                obj_info = find_obj_info(match_obj.group(1))
                self.var_dict[var_key] = [match_obj.group(1), obj_info]
                
                if self.debug:
                    print('[Debug] =========================================================================================================')              
                    print('var_dict[{0}] : {1}  {2}'.format(var_key, match_obj.group(1), obj_info))              
                    print('=================================================================================================================')     

    def show_var_dict(self):
        if self.debug and len(self.var_dict.keys()):
            print('[Debug] =========================================================================================================')              
            for var_key in sorted(self.var_dict.keys()):
                val = self.var_dict[var_key]
                print('    {0} : {1} {2}'.format(var_key, val[0], val[1]))
            print('=================================================================================================================')              
            
    def get_acl_counter_info(self):   
        if self.acl_counter:
            self.set_path_sai_acl()
            time.sleep(0.5)
            for counter_name in self.acl_counter:
                if counter_name not in self.acl_counter_info:
                    return False

                acl_counter_id, _ = self.acl_counter_info[counter_name]
                cmd = 'sai_get_acl_counter_attribute ' + acl_counter_id + ' SAI_ACL_COUNTER_ATTR_PACKETS 1'
                found = False
                while not found:
                    cmd_result_list = self.cmd2(cmd, self.enable_log)
                    for cmd_result in cmd_result_list:
                        if cmd_result.find(acl_counter_id) != -1:
                            match_obj = re.match(r'\s*(\d+)\s*', cmd_result_list[-1])
                            if match_obj:
                                self.acl_counter_info[counter_name] = (acl_counter_id, int(match_obj.group(1)))
                                found = True
                            break
        return True

    def check_acl_counter_info(self):

        if self.acl_counter:
            self.set_path_sai_acl()
            time.sleep(0.5)

            for counter_name in self.acl_counter:
                if counter_name not in self.acl_counter_info:
                    return False

                acl_counter_id, pre_count = self.acl_counter_info[counter_name]
                cmd = 'sai_get_acl_counter_attribute ' + acl_counter_id + ' SAI_ACL_COUNTER_ATTR_PACKETS 1'
                found = False
                while not found:
                    cmd_result_list = self.cmd2(cmd, self.enable_log)
                    for cmd_result in cmd_result_list:
                        if cmd_result.find(acl_counter_id) != -1:                        
                            match_obj = re.match(r'\s*(\d+)\s*', cmd_result_list[-1])
                            if match_obj:
                                if (int(match_obj.group(1)) - pre_count) != self.packet_count:
                                    return False
                                found = True
                            break

            if self.enable_log:
                print ("Acl Counters incremented as expected !")

        return True

    def check_test_result(self):   
        error_count = 0;
        for i in range(self.expected_count):
            name = 'expect{0}'.format(i+1)
            if name in self.expected_data:

                value_str = self.expected_data[name]
                if '$' in value_str:
                    var_list = re.findall(r'[\$]\w+', value_str)
                    for var in var_list:
                        value_str = value_str.replace(var, self.var_dict[var.strip('$')][0])
                    value_str = '{0}'.format(eval(value_str))
                    
                if not comparestr(self.last_cmd_result, value_str):
                    print('expected data {0} mismatched'.format(i+1))
                    error_count = error_count + 1
                else:
                    print('expected data {0} matched'.format(i+1))
                        
        return True if error_count == 0 else False
        
    def check_mac_counters(self, port):

        print('check_mac_counters - port {0}'.format(port))
        cmd_result = self.get_mac_counters(port)
        rx_res, _ = parse_mac_counters(cmd_result)
        if self.packet_count not in rx_res:
            print("packets not correctly received at the Ingress Port")
            return False

        for egr_port in self.egress_port:
            if egr_port == port:
                print("Mac counters matched")
                return True

            print('check_mac_counters - port {0}'.format(egr_port))
            cmd_result = self.get_mac_counters(egr_port)
            _, egr_tx_res = parse_mac_counters(cmd_result)
            if  self.packet_count not in egr_tx_res:
                print("packets not correctly egressed out of the Egress Port")
                return False

        print("Mac counters matched")
        return True

    def check_cpu_counter(self):
        cpu_rx_count = self.get_cpu_rx_counter()
        if (cpu_rx_count - self.cpu_rx_count) == self.packet_count:
            return True
        return False

    def init_test_enale_egress_ports(self):    
        if not self.egress_port:
            return

        for egr_port in self.egress_port:
            if egr_port != '':
                self.set_port_enable(egr_port)

    def init_test_counters(self, port):
        for egr_port in self.egress_port:
            if egr_port != '':
                self.clear_mac_counters(egr_port)
        self.clear_mac_counters(port)
        self.clear_cpu_stat()
        self.cpu_rx_count = self.get_cpu_rx_counter()
        self.get_acl_counter_info()

    def telnet_connect(self):
        self.telnet_intf = SshConnection(self.ip, self.user, self.passwd)

    def telnet_set_prompt(self, prompt):
        self.telnet_intf.set_prompt_for_expect(prompt)

    def telnet_cmd(self, command, allow_print=True, sleep=False, kill_apptest=False):
        return self.telnet_intf.cmd(command, allow_print, sleep, kill_apptest)

    def connect(self):    
        self.ssh_connect()
        try:
            cd_xdk_dir = 'cd ' + self.path_xdk
            self.cmd(cd_xdk_dir)
            self.cmd("sudo su")
            self.ssh_set_prompt('(\(xpShell\))')
            self.cmd(self.run_app, True, False, True)
        except Exception as e:
            print(e)
            sys.exit()
        
        self.telnet_connect()
        try:
            self.telnet_cmd("sudo su")
            connect_str = "telnet 127.0.0.1 {0}".format(self.port)
            self.telnet_set_prompt('Console.*#')
            self.telnet_cmd(connect_str, True, False, True)
            '''
            self.telnet_cmd('debug-mode', True, False, True)
            self.telnet_cmd('simulation startSimulationLog full-path-name /home/lamp4you/project/marvell/source/sai-M1/mrvl-sai/apptest/aldrin_logger.txt', True, False, True)
            '''
        except Exception as e:
            print(e)
            sys.exit()              

    def close(self):
        if self.telnet_intf:
            self.telnet_intf.close()
            self.telnet_intf = None
        if self.ssh_intf:
            self.ssh_intf.close()
            self.ssh_intf = None

