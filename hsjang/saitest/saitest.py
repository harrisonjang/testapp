# coding=utf-8

import sys
import os
import argparse
import json
import pexpect
import imp
import testList
import testListFeature
import re
from datetime import datetime
from threading import Thread
from time import sleep
from collections import defaultdict
import time
import pdb
import sys

try:
   import scapy.all as t_scapy
except IOError:
   print("Caught Exception IOError")

try:
    from pexpect import pxssh as pxssh
except:
    print("pxssh is not installed, if you want to run apptest on Hw and testScript method please install it")

TESTS_PREFIXES = ["saiCrm", "saiFdb", "saiL3", "saiQos", "saiEverflow", "saiIngrAcl", "saiEgrAcl", "saiMac", "saiPort"]

from saiobjid import *
from saiTestUnit import *

class FileLogger(object):
    def __init__(self, log_dir, log_name):
        self.terminal = sys.stdout
        if not os.path.exists(log_dir) or not os.path.isdir(log_dir):
            os.makedirs(log_dir)
        ext = os.path.splitext(log_name)[1]
        if ext is None or ext.strip() == '':
            log_name = '{}.txt'.format(log_name)
        self.log_path = os.path.abspath(os.path.join(log_dir, log_name))
        self.log = open(self.log_path, 'a')
        print("Initiated log file: {}".format(self.log_path))

    def write(self, msg):
        self.terminal.write(msg)
        self.log.write(msg)

    def flush(self):
        self.log.close()


class RunData(object):
    def __init__(self, total=0):
        self.total = total
        self.passed = 0
        self.failed = 0
        self.ioerror = 0
        self.executed = 0
        self.tests = []
        self.failed_testcase_list = []
        self.ioerror_testcase_list = []

    def add_result(self, test_name, status_str, run_time):
        test_name_org = test_name
        test_prefix = next((x for x in TESTS_PREFIXES if x in test_name),None)
        if test_prefix is not None:
            test_name = test_name.replace(test_prefix, test_prefix + '_')

        if 'pass' in status_str.lower():
            self.passed = self.passed + 1
        else:
            self.failed = self.failed + 1
            self.failed_testcase_list.append(test_name)
        self.executed = self.executed + 1
        log_path = sys.stdout.log_path if isinstance(sys.stdout, FileLogger) else None
        self.tests.append({'name': test_name, 'status': status_str, 'time': int(round(run_time)), "log": log_path})
        print("Test {0} ({1}) {2} ({3}){4}{4}".format(test_name, test_name_org, status_str, run_time, os.linesep))

    def add_ioerror(self, test_name):
        self.ioerror = self.ioerror + 1
        self.ioerror_testcase_list.append(test_name)

    def get_json(self):
        return json.dumps(self.tests, indent=4, sort_keys=True)

    def print_summary(self):
        print('--------------- TEST SUMMARY ---------------')
        print('***Total Test Cases***\t\t' + str(self.total))
        print('***Test Cases Executed***\t' + str(self.executed))
        print('***Test Cases Passed***\t\t' + str(self.passed))
        print('***Test Cases Failed***\t\t' + str(self.failed))
        print('***Test Cases IOError***\t' + str(self.ioerror))
        print('--------------------------------------------')
        if self.failed != 0:
            print('--------------- FAILED TEST CASES ---------------\n')
            for x in range(len(self.failed_testcase_list)):
                print('\t' + str(self.failed_testcase_list[x]))
        if self.ioerror != 0:
            print('--------------- IOERROR TEST CASES ---------------\n')
            for x in range(len(self.ioerror_testcase_list)):
                print('\t' + str(self.ioerror_testcase_list[x]))


def usage():
    print("python saitest.py [options]")
    print('    [options]')
    print('        --ip=<ipaddr>')
    print('        --user=<username>')
    print('        --passwd=<passwd>')
    print('        --xdk_path=<xdk_path>      : absolute path to xdk ex "/home/xdk/"')
    print('        --devtype=<devtype>        : ac5p, falcon')
    print("        --testtype=<testType>      : feature, ")
    print("        --testname=<testName>      : all(if all testcase to be executed)/<name of testcase>")
    print("        --log=<enable_log>")
    print("        --config=<config file>")
    cleanup()
    sys.exit()


test_list_info = {
    "feature": testListFeature.featureRegressionUT,
    "sanity": testList.regressionUT,
    "crm": testListFeature.crm_featureRegressionUT,
    "fdb": testListFeature.fdb_featureRegressionUT,
    "mtu": testListFeature.mtu_featureRegressionUT,
    "l3": testListFeature.l3_featureRegressionUT,
    "everflow": testListFeature.everflow_featureRegressionUT,
    "acl": testListFeature.acl_featureRegressionUT,
    "qos": testListFeature.qos_featureRegressionUT,
    "mac": testListFeature.mac_featureRegressionUT,
    "misc": testListFeature.misc_featureRegressionUT,
    "test": testListFeature.test_featureRegressionUT
}


class SaiTest(object):

    def __init__(self, argment):

        # default
        self.LOGS_DIR = None

        # configuration
        self.testtype = None
        self.testname = None
        self.curr_testname = None
        self.debug = True
        self.enable_log = True
        self.dev_type = "Aldrin3-XL"
        self.config_info = None
        self.test_list = None
        self.run_app = None
        self.run_data = None

        # test
        self.test_unit = None
        self.cmd_list = None
        self.flush_list = None
        self.test_case_loop = []
        self.start_time = None
        self.cpu_rx_count = 0
        self.packet_count = 0
        self.packet_action = None
        self.ingress_packet = None
        self.ingress_port = None
        self.egress_port = None
        self.i_tap = None
        self.e_taps = None
        self.expected_count = 0
        self.packet_info = None
        self.pkt_keys = None
        self.captured_packet = None
        self.expected_data = None

        config_file = argment.config
        print('config_file = %s' % config_file)
        if not os.path.exists(config_file) or not os.path.isfile(config_file):
            print("file %s not found" % config_file)
            usage()

        # load json file
        config_file_f = open(config_file)
        self.config_info = json.load(config_file_f)
        config_file_f.close()

        self.config_info['ip'] = argment.ip if argment.ip is not None else self.config_info['ip']
        self.config_info['port'] = argment.port if argment.port is not None else self.config_info['port']
        self.config_info['user'] = argment.user if argment.user is not None else self.config_info['user']
        self.config_info['passwd'] = argment.passwd if argment.passwd is not None else self.config_info['passwd']
        self.config_info['path_xdk'] = argment.path_xdk if argment.path_xdk is not None else self.config_info['path_xdk']
        self.config_info['devtype'] = argment.devtype if argment.devtype is not None else self.config_info['devtype']
        self.config_info['testtype'] = argment.testtype if argment.testtype is not None else self.config_info['testtype']
        self.config_info['testname'] = argment.testname if argment.testname is not None else self.config_info['testname']
        self.config_info['log'] = argment.log if argment.log is not None else self.config_info['log']
        self.config_info['debug'] = argment.debug if argment.debug is not None else self.config_info['debug']

        # devType
        self.enable_log = True if self.config_info['log'] in ['True', 'Yes', 'Enable', '1'] else False
        self.debug = True if self.config_info['debug'] in ['True', 'Yes', 'Enable', '1'] else False

        self.dev_type = "Aldrin3-XL" if self.config_info['devtype'] == "ac5p" else "Falcon"

        self.LOGS_DIR = os.path.join("TestResults", datetime.now().strftime(self.dev_type + "-%m.%d.%Y_%H"))
        print("Run results location: {}".format(os.path.abspath(self.LOGS_DIR)))

        if self.config_info['devtype'] == "ac5p":
            self.run_app = "./dist/xpSaiApp -w -g AC5P32x25G"
        else:
            self.run_app = "./dist/xpSaiApp -g FALCON128 -u"
        self.config_info['run_app'] = self.run_app

        self.testtype = self.config_info['testtype']
        self.testname = self.config_info['testname']
        self.test_list = self.get_test_list()
        if len(self.test_list) == 0:
            print("No test to run. Test list empty.")
            cleanup()
            sys.exit()

        self.run_data = RunData(len(self.test_list))
        self.test_unit = SaiTestUnit(self.config_info)

    def init_test_variables(self):

        self.flush_list = None
        self.packet_count = 0
        self.packet_action = None
        self.ingress_packet = None
        self.ingress_port = None
        self.egress_port = None
        self.i_tap = None
        self.e_taps = None
        self.expected_count = 0
        self.packet_info = None
        self.pkt_keys = None
        self.captured_packet = None
        self.expected_data = None

    def get_test_list(self):

        if self.testtype in test_list_info:
            test_list = test_list_info[self.testtype]
        else:
            print("Invalid argument for testType. Taking sanity as default")
            test_list = testList.regressionUT

        if self.testname != 'all':
            test_list = [self.testname]

        print('test_list = {0}'.format(test_list))
        return test_list

    def connect_dut(self):
        self.test_unit.connect()

    def load_test_module(self):

        # print('load_test_module')
        self.init_test_variables()

        # set test_path
        test_name = self.curr_testname
        test_filename = "{}.py".format(test_name)
        if self.dev_type == "Aldrin3-XL":
            test_path = "testAc5pCases{}{}".format(os.sep, test_filename)
        else:
            test_path = "testCases{}{}".format(os.sep, test_filename)

        try:
            print("Loading test {} from {}".format(test_name, test_path))
            mod = imp.load_source(test_filename, test_path)
        except Exception as e:
            print(e)
            print("<<<<<<Unknown Exception occured!!!>>>", test_name)
            return False

        if not mod.tcParams:
            return False

        self.test_unit.init_test_data(mod)
        self.test_case_loop = self.test_unit.init_test_case_loop(mod)

        if 'sleep_time' in mod.tcParams.keys():
            sleepTime = mod.tcParams['sleep_time']
            print ("Recieved sleep time of " + str(sleepTime) + " seconds")
            sleep(sleepTime)
            print ("sleep step completed")

        self.acl_counter = mod.tcParams['acl_counter'] if 'acl_counter' in mod.tcParams else None
        self.packet_count = mod.tcParams['packetCount'] if 'packetCount' in mod.tcParams else 1
        self.packet_action = mod.tcParams['pktAction'] if 'pktAction' in mod.tcParams else None
        self.ingress_packet = mod.tcParams['ingressPacket'] if 'ingressPacket' in mod.tcParams and mod.tcParams['ingressPacket'] != '' else None
        self.ingress_port = mod.tcParams['ingressPort'] if 'ingressPort' in mod.tcParams else None
        self.egress_port = mod.tcParams['egressPort'] if 'egressPort' in mod.tcParams else None
        self.i_tap = mod.tcParams['ingressTapIntf'] if 'ingressTapIntf' in mod.tcParams else None
        self.e_taps = mod.tcParams['egressTapIntf'] if 'egressTapIntf' in mod.tcParams else None
        self.expected_count = mod.tcParams['count'] if 'count' in mod.tcParams else None

        # test packet information
        self.packet_info = mod.packet_info if hasattr(mod, 'packet_info') else None

        # expected data information
        self.expected_data = mod.expectedData if hasattr(mod, 'expectedData') else None

        return self.make_cmd_list(mod)

    def make_cmd_list(self, mod):

        # print('make_cmd_list')
        if not hasattr(mod, 'tcProgramStr'):
            return False

        cmd_list = mod.tcProgramStr.split('\n')
        self.cmd_list = [x for x in cmd_list if x.strip()]

        if hasattr(mod, 'tcFlushStr'):
            flush_list = mod.tcFlushStr.split('\n')
            self.flush_list = [x for x in flush_list if x.strip()]

        return True

    def check_packet_drop(self, igr_port):
        print('check_packet_drop - port {0}'.format(igr_port))
        if self.test_unit.check_mac_counters(igr_port):
            print("Mac counters matched in DROP case implies drop is not happening")
            self.run_data.add_result(self.curr_testname, 'Failed', (datetime.now() - self.start_time).total_seconds())
            return False
        else:
            self.run_data.add_result(self.curr_testname, 'Passed', (datetime.now() - self.start_time).total_seconds())
            return True

    def check_packet_forward(self, port):
        error_count = 0

        pkt_keys = sorted(self.captured_packet.keys())
        for i in range(self.expected_count):
            name = 'expect{0}'.format(i+1)
            if self.pkt_keys and self.e_taps:
                captured_data = "'{0}':{1}".format(pkt_keys[i], self.captured_packet[self.e_taps[i]])
                if comparestr(captured_data, self.expected_data[name]):
                    print('expected data {0} matched'.format(i))
                else:
                    print('expected data {0} mismatched'.format(i))
                    error_count = error_count + 1
            else:
                  print('No packets are captured by the sniffer')

        if error_count == 0:
            if self.test_unit.check_mac_counters(port):
                self.run_data.add_result(self.curr_testname, 'Passed', (datetime.now() - self.start_time).total_seconds())
                return True
            else:
                print("MAC counters mismatched")
                self.run_data.add_result(self.curr_testname, 'Failed', (datetime.now() - self.start_time).total_seconds())
                return False
        else:
            self.run_data.add_result(self.curr_testname, 'Failed', (datetime.now() - start_time).total_seconds())
            return False

    def check_packet_trap(self):    
        if self.test_unit.check_cpu_counter():
            self.run_data.add_result(self.curr_testname, 'Passed', (datetime.now() - self.start_time).total_seconds())
            return True
        else:
            print("CPU counters not Updated")
            self.run_data.add_result(self.curr_testname, 'Failed', (datetime.now() - self.start_time).total_seconds())
            return False

    def check_packet_action(self, port):
        pkt_action = self.packet_action
        if pkt_action == 'DROP':
            return self.check_packet_drop(port)
        elif pkt_action == 'FORWARD':
            return self.check_packet_forward(port)
        elif pkt_action == 'FORWARD AND MIRROR':
            return self.check_packet_forward(port)
        elif pkt_action == 'TRAP':
            return self.check_packet_trap()
        return False
        
    def test_dataflow(self):

        if not self.ingress_packet:
            return True

        # print("wait 10 secs")
        # time.sleep(10)
        
        self.test_unit.set_path_xps_packetdrv()
        self.test_unit.cmd("packet_driver_receive 10", self.enable_log)

        result = True
        self.test_unit.init_test_enale_egress_ports()
        for igr_port in self.ingress_port:

            self.test_unit.init_test_counters(igr_port)
            self.test_unit.set_port_enable(igr_port)

            pkts = defaultdict(list)
            if self.e_taps:
                etap_list = self.e_taps if isinstance(self.e_taps, list) else list(self.e_taps)
                t = t_scapy.AsyncSniffer(iface=etap_list, count=int(self.expected_count), prn=lambda x: pkts[x.sniffed_on].append(x), timeout=10)
                t.start()
                sleep(1)

            t_scapy.sendp(self.packet_info, iface=self.i_tap, count=self.packet_count)
            sleep(4)

            if (self.e_taps):
                t.join()

            self.captured_packet = pkts
            if self.enable_log:
                print("packets sniffed after AsyncSniffer stopped")
                print(pkts)

            if not self.test_unit.check_acl_counter_info():
                self.run_data.add_result(self.curr_testname, 'Failed in Acl Counter check', (datetime.now() - self.start_time).total_seconds())
                result = False
                break

            if not self.check_packet_action(igr_port):
                result = False
                break

        return result

    def flush_all(self):
        self.flush_local()
        self.flush()

    def flush_local(self):
        pass

    def flush(self):

        flush_list = self.flush_list
        for cmd in flush_list:
            if self.enable_log:
                print(cmd)

            cmd_result = self.test_unit.cmd3(cmd, False)
            cmd_result = cmd_result.replace(cmd, "")
            if self.enable_log:
                print(cmd_result)

            if cmd_result.find("invalid") != -1:
                print("invalid input : {0} - result {1}".format(cmd, cmd_result))

            if cmd_result.find("error") != -1:
                print("command error : {0} - result {1}".format(cmd, cmd_result))

    def cleanup(self):
        LOGS_DIR = self.LOGS_DIR
        CMD = "chmod -R a+rwx " + LOGS_DIR
        os.system(CMD)
        CMD = "find . -name '*.pyc' | xargs chmod a+rwx "
        os.system(CMD)

    def run_test(self):

        self.test_unit.set_log_level(2)
        if self.config_info['devtype'] == "ac5p":
            self.test_unit.ac5p_workround(True)

        print('run_test : test_list = {0}'.format(self.test_list))
        for test_name in self.test_list:

            self.curr_testname = test_name
            original_out = sys.stdout
            sys.stdout = FileLogger(self.LOGS_DIR, test_name)

            try:
                self.run_test_case()
            except IndexError as e:
                print(e)
                print(">>>>>>%s Exception occured!!!" % test_name)
                try:
                    self.run_data.add_ioerror(test_name)
                except:
                    pass
            except IOError as e:
                print(e)
                print(">>>>>>%s Exception occured!!!" % test_name)
                try:
                    self.run_data.add_ioerror(test_name)
                except Exception as e:
                    print(e)
                    pass
            except Exception as e:
                print(e)
                print("<<<<<<Unknown Exception occured!!!>>>", test_name)
                sys.stdout = original_out
                break

            sys.stdout = original_out

        with open(os.path.join(self.LOGS_DIR, "results.json"), 'a+') as f:
            print("Results recorded to {}".format(os.path.abspath(f.name)))
            f.write(self.run_data.get_json())

        self.run_data.print_summary()

    def run_test_case(self):

        self.start_time = datetime.now()
        self.load_test_module()

        loop_info_len = len(self.test_case_loop)
        error_count = 0

        print('run_test_case - {}'.format(self.curr_testname))
        print('loop_info = {0}'.format(self.test_case_loop))

        for idx in range(loop_info_len):

            for cmd in self.cmd_list:
                if not self.test_unit.command(cmd, self.test_case_loop[idx], False):
                    error_count = error_count + 1
                    break

            if error_count > 0:
                break

            if not self.test_unit.get_acl_counter_info():
                error_count = error_count + 1
                break

            self.test_unit.show_var_dict()

            if self.ingress_packet:
                if not self.test_dataflow():
                    error_count = error_count + 1
                    break
            else:
                if not self.test_unit.check_test_result():
                    error_count = error_count + 1
                    break

        self.flush_all()
        if not self.ingress_packet:
            status_str = 'Passed' if error_count == 0 else 'Failed'
            self.run_data.add_result(self.curr_testname, status_str, (datetime.now() - self.start_time).total_seconds())

    def close(self):
        self.test_unit.close()


def make_argparser():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--ip', action='store', dest='ip', help='ip of the board where xdk is copied')
    argparser.add_argument('--port', action='store', dest='port', help='...')
    argparser.add_argument('--user', action='store', dest='user', help='user name (root)')
    argparser.add_argument('--passwd', action='store', dest='passwd', help='passwd for user name if no password please pass')
    argparser.add_argument('--path_xdk', action='store', dest='path_xdk', help='absolute path to xdk ex "/home/xdk/"')
    argparser.add_argument('--devtype', action='store', dest='devtype', help='device type')
    argparser.add_argument('--testtype', action='store', dest='testtype', help='...')
    argparser.add_argument('--testname', action='store', dest='testname', help='for now give all')
    argparser.add_argument('--log', action='store', dest='log', help='for now give all')
    argparser.add_argument('--config', action='store', dest='config', help='configuration', default="testdefault.json")
    argparser.add_argument('--debug', action='store', dest='debug', help='debug')
    return argparser


if __name__ == "__main__":

    argparser = make_argparser()
    argparse_result = argparser.parse_args()
    saitest = SaiTest(argparse_result)

    saitest.connect_dut()
    saitest.run_test()
    saitest.close()

