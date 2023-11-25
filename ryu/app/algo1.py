# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ether_types


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.known_hosts = {}
        self.arp_attempts = {}

    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath,  src ):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        _arp = pkt.get_protocol(arp.arp)
        _tcp = pkt.get_protocol(tcp.tcp)
        _udp = pkt.get_protocol(udp.udp)


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)
        if _ipv4:
           dstip = _ipv4.dst
           srcip = _ipv4.src
           self.logger.info("packet in dpid=%s src=%s dst=%s srcMac=%s dstMAc=%s port=%s proto=%s", dpid, srcip, dstip, src, dst, msg.in_port, _ipv4.proto)
           self.known_hosts[srcip]=src
           self.known_hosts[dstip]=dst

        if _tcp:
           self.logger.info("packet in dpid=%s src=%s dst=%s srcMac=%s dstMAc=%s port=%s proto=%s in_tcp_port=%s out_tcp_port=%s", dpid, srcip, dstip, src, dst, msg.in_port, _ipv4.proto, _tcp.src_port, _tcp.dst_port)

        if _udp:
           self.logger.info("packet in dpid=%s src=%s dst=%s srcMac=%s dstMAc=%s port=%s proto=%s in_udp_port=%s out_udp_port=%s", dpid, srcip, dstip, src, dst, msg.in_port, _ipv4.proto, _udp.src_port, _udp.dst_port)


        if _icmp:
           self.logger.info(_icmp)

        if _arp:
           self.logger.info(_arp)
           self.logger.info("known_hosts")
           self.logger.info(self.known_hosts)
           if _arp.src_ip in self.known_hosts:
               if _arp.src_ip in self.arp_attempts and _arp.dst_ip not in self.known_hosts:
                   if self.arp_attempts[_arp.src_ip] > 4:
                       self.logger.info("The IP Address %s in port %s of switch dpid %s maybe a ARP attacker",_arp.src_ip,msg.in_port,dpid)
                       self.add_drop_flow(datapath,src)
                   self.arp_attempts[_arp.src_ip]=self.arp_attempts[_arp.src_ip]+1
               else:
                    self.arp_attempts[_arp.src_ip]=1
           else:
               self.logger.info("port %s in switch with dpid %s may be attempting some MAC attack",msg.in_port,dpid)


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
