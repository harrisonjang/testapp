# coding=utf-8

import sys
import os
import pexpect
from time import sleep
import time
import re

try:
    from pexpect import pxssh as pxssh
except:
    print("pxssh is not installed, if you want to run apptest on Hw and testScript method please install it")

winsize_row = 128
winsize_col = 256

class SshConnection(object):
    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        try:
            self.ssh_conn = self.ssh_conn(self.hostname, self.username, self.password)
            self.ssh_conn.PROMPT = "[#>$]\s+$"
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
    def cmd(self, command, allowPrint=True, sleeptime=-1, killApptest=False, debug=False):
        prompt_repeat = 0
        buff_pos = 0
        retries = self.ssh_conn.timeout
        tmpbuf = ''
        self.ssh_conn.buffer = ''
        
        self.ssh_conn.sendline(command)
        time.sleep(0.1)
        if command.find("exit") != -1:
            return self.ssh_conn.before
        if sleeptime > 0:
            time.sleep(sleeptime)
          
        prompt_repeat = 0
        while prompt_repeat < retries:
            try:
                read_bytes = self.ssh_conn.read_nonblocking(256, timeout=1)
                if debug:
                    print('{0}'.format(read_bytes))
                
                tmpbuf = tmpbuf + read_bytes                    
                srch_obj = re.search(self.ssh_conn.PROMPT, tmpbuf)
                if srch_obj:
                    if allowPrint:
                        print('{0}'.format(tmpbuf))
                    return tmpbuf    
            except pexpect.exceptions.TIMEOUT as e:                               
                prompt_repeat = prompt_repeat + 1
                pass

        print("Failed to detect prompt %s for %s times" % (self.ssh_conn.PROMPT, retries))
        print(tmpbuf)
        if killApptest:
            print("=" * 100)
            print(
                "Failed to detect prompt %s for %s times for %s cmd" % (self.ssh_conn.PROMPT, retries, command))
            print("=" * 100)
            cleanup()
            sys.exit()
        return ''                

    def set_prompt_for_expect(self, prompt):
        self.ssh_conn.PROMPT = prompt

    def close(self):
        try:
            self.ssh_conn.close()
            print("connection to %s closed" % self.hostname)
        except Exception as err:
            print(err)
            sys.exit()


