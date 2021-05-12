import scapy.all as scapy_t
#
#tcParams: This dictionary contains parameters to be used, in order to configure specific
#          networking scenario, in future it can be used to auto generate spirent streams.

tcParams = {
    'ingressPacket'  : 'L4Packet',
    'tcName'         : 'saiEgrAclParallelLookup',
    'description'    : 'TC to verify Ingress drop Acl Table Entry for Parallel lookup',
    'ingressPort'    : ['53'],
    'egressPort'     : ['54'],
    'vlan'           : '75',
    'pktAction'      : 'DROP',
    'ingressTapIntf' : 'tap1',
    'egressTapIntf'  : ['tap2'],
    'count'          : 0,             # expected data count
    'acl_counter'    : ['acl_counter_id0','acl_counter_id1','acl_counter_id2','acl_counter_id3'] #only for acl cases
}


#
#tcProgramStr: This string contains chain of xpShell commands to be used, in order to configure
#              specific networking scenario.

tcProgramStr = '''
home
sai
vlan
sai_create_vlan &switch0 75 > vlan75
sai_create_vlan_member &switch0 $vlan75 &bridgeport53 1 > memtap0
back
port
sai_set_port_attribute &port52 SAI_PORT_ATTR_ADMIN_STATE 1
sai_set_port_attribute &port53 SAI_PORT_ATTR_ADMIN_STATE 1
sai_set_port_attribute &port54 SAI_PORT_ATTR_ADMIN_STATE 1
back
lag
sai_create_lag &switch0 1 > lag0
sai_create_lag_member &switch0 &port54 $lag0 > mem30
back
switch
sai_get_switch_attribute &switch0 SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID 1 > brg
back
bridge
sai_create_bridge_port &switch0 0 $lag0 $brg SAI_BRIDGE_PORT_TYPE_PORT 0 0 > brgportlag
back
vlan
alter_create_mode 1
sai_create_vlan_member &switch0 $vlan75 $brgportlag 1 > memtap1
back
acl
alter_create_mode 0
sai_create_acl_table_group &switch0 SAI_ACL_STAGE_EGRESS [] 1 > acl_table_group
sai_create_acl_table &switch0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 > acl_tbl_id0

sai_create_acl_counter &switch0 $acl_tbl_id0 1 1 > acl_counter_id0

sai_create_acl_entry &switch0 $acl_tbl_id0 10 > acl_entry_id0
sai_set_acl_entry_attribute $acl_entry_id0 SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT 1 65535 2567
sai_set_acl_entry_attribute $acl_entry_id0 SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION 1 SAI_PACKET_ACTION_DROP
sai_set_acl_entry_attribute $acl_entry_id0 SAI_ACL_ENTRY_ATTR_ACTION_COUNTER 1 $acl_counter_id0

sai_create_acl_table &switch0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 > acl_tbl_id1

sai_create_acl_counter &switch0 $acl_tbl_id1 1 1 > acl_counter_id1

sai_create_acl_entry &switch0 $acl_tbl_id1 11 > acl_entry_id1
sai_set_acl_entry_attribute $acl_entry_id1 SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT 1 65535 2569
sai_set_acl_entry_attribute $acl_entry_id1 SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION 1 SAI_PACKET_ACTION_DROP
sai_set_acl_entry_attribute $acl_entry_id1 SAI_ACL_ENTRY_ATTR_ACTION_COUNTER 1 $acl_counter_id1

sai_create_acl_table &switch0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 > acl_tbl_id2

sai_create_acl_counter &switch0 $acl_tbl_id2 1 1 > acl_counter_id2

sai_create_acl_entry &switch0 $acl_tbl_id2 12 > acl_entry_id2
sai_set_acl_entry_attribute $acl_entry_id2 SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP 1 255.255.255.255 100.1.1.1
sai_set_acl_entry_attribute $acl_entry_id2 SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION 1 SAI_PACKET_ACTION_DROP
sai_set_acl_entry_attribute $acl_entry_id2 SAI_ACL_ENTRY_ATTR_ACTION_COUNTER 1 $acl_counter_id2

sai_create_acl_table &switch0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 > acl_tbl_id3

sai_create_acl_counter &switch0 $acl_tbl_id3 1 1 > acl_counter_id3

sai_create_acl_entry &switch0 $acl_tbl_id3 11 > acl_entry_id3
sai_set_acl_entry_attribute $acl_entry_id3 SAI_ACL_ENTRY_ATTR_FIELD_DST_IP 1 255.255.255.255 100.1.1.2
sai_set_acl_entry_attribute $acl_entry_id3 SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION 1 SAI_PACKET_ACTION_DROP
sai_set_acl_entry_attribute $acl_entry_id3 SAI_ACL_ENTRY_ATTR_ACTION_COUNTER 1 $acl_counter_id3

back
port
sai_set_port_attribute &port54 SAI_PORT_ATTR_EGRESS_ACL $acl_table_group
back
acl
sai_create_acl_table_group_member &switch0 $acl_tbl_id0 $acl_table_group 0 >acl_table_group_mem1
sai_create_acl_table_group_member &switch0 $acl_tbl_id1 $acl_table_group 0 >acl_table_group_mem2
sai_create_acl_table_group_member &switch0 $acl_tbl_id2 $acl_table_group 0 >acl_table_group_mem3
sai_create_acl_table_group_member &switch0 $acl_tbl_id3 $acl_table_group 0 >acl_table_group_mem4

'''


#
#tcFlushStr: This string contains chain of xpShell commands to be used, in order to remove
#            specific networking scenario.

tcFlushStr = '''
home
sai
acl
sai_remove_acl_entry $acl_entry_id0
sai_remove_acl_counter $acl_counter_id0
sai_remove_acl_entry $acl_entry_id1
sai_remove_acl_counter $acl_counter_id1
sai_remove_acl_entry $acl_entry_id2
sai_remove_acl_counter $acl_counter_id2
sai_remove_acl_entry $acl_entry_id3
sai_remove_acl_counter $acl_counter_id3
sai_remove_acl_table_group_member $acl_table_group_mem1
sai_remove_acl_table_group_member $acl_table_group_mem2
sai_remove_acl_table_group_member $acl_table_group_mem3
sai_remove_acl_table_group_member $acl_table_group_mem4
sai_remove_acl_table $acl_tbl_id0
sai_remove_acl_table $acl_tbl_id1
sai_remove_acl_table $acl_tbl_id2
sai_remove_acl_table $acl_tbl_id3
back
port
sai_set_port_attribute &port54 SAI_PORT_ATTR_EGRESS_ACL 0
back
acl
sai_remove_acl_table_group $acl_table_group
back
vlan
sai_remove_vlan_member $memtap0
sai_remove_vlan_member $memtap1
sai_remove_vlan $vlan75
back
bridge
sai_remove_bridge_port $brgportlag
back
lag
sai_remove_lag_member $mem30
sai_remove_lag $lag0
back
home

'''

packet_info = scapy_t.Ether(src="00:00:11:00:11:00",dst="00:00:11:00:11:23")/scapy_t.Dot1Q(vlan =75)/scapy_t.IP(src="100.1.1.1",dst="100.1.1.2")/scapy_t.TCP(sport=2567,dport=2569)

#
#expectedData: This dictionary expected egress stream for each egress port.
#

expectedData = {
       'expect1':'',
}

