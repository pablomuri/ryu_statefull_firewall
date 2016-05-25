"""
An OpenFlow 1.0  L2 stealth firewall implementation.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


PROTO_TCP = 6
PROTO_UDP = 17
ETH_ARP = 0x0806
ETH_IP = 0x0800
PORT_DNS = 53
PORT_WEB = 80

HOST_WEB = "10.0.0.10"

FW_OUTPORT = 2
FW_INPORTS = [1,3]

class Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.states = {}


    def add_flow(self, datapath, match, out_port, idle_to, hard_to):
        ofproto = datapath.ofproto

        if out_port:
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        else:
            actions = []

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=idle_to, hard_timeout=hard_to,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]        

            # install a flow to avoid packet_in next time
            #ARP Packets......................................................................
            '''
            if eth.ethertype == ETH_ARP:
                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_type = ETH_ARP,
                    dl_src=haddr_to_bin(src), dl_dst=haddr_to_bin(dst))
                #self.add_flow(datapath, match, out_port, 5, 0)
                self.forwardPacket(msg, out_port)
            '''
            
            # IP Packets.......................................................................
            if eth.ethertype == ETH_IP:
                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_type = ETH_IP, 
                    dl_src=haddr_to_bin(src), dl_dst=haddr_to_bin(dst)) 

                if (msg.in_port in FW_INPORTS) or (self.match_in_states(out_port, match, datapath)):
                    if msg.in_port in FW_INPORTS:
                        self.add_match_state(out_port, match)

                    #self.add_flow(datapath, match, out_port, 5, 0)
                    #self.forwardPacket(msg, out_port)
                else :
                    #DROP packets
                    #add flow and packet_out with no actions
                    self.add_flow(datapath, match, None, 5, 0)
                    self.forwardPacket(msg, None)

        #flood packet if ARP..................................................................
        '''
        else: 
            out_port = ofproto.OFPP_FLOOD
            if eth.ethertype == ETH_ARP:
                #if packet is ARP, foward packet (flood ports)
                self.forwardPacket(msg, out_port)
        '''

    def match_in_states(self, out_port, match, datapath):
        if match['in_port'] in self.states:
            for m in self.states[match['in_port']]:
                if ((match['dl_src'] == m['dl_dst']) and (match['dl_dst'] == m['dl_src']) and (m['in_port'] == out_port)):
                    return True  
        
        return False

    def add_match_state(self, out_port, match):
        #TODO add cookie for better identification
        if out_port in self.states:
            self.states[out_port].append(match)
        else:
            self.states[out_port] = [match]



    def forwardPacket(self, msg, outPort):
        # Does not install a rule. Just forwards this packet.
        datapath=msg.datapath

        ofproto = datapath.ofproto

        data=None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        if msg.buffer_id is not ofproto.OFP_NO_BUFFER:
            if not outPort:
                po_actions =[] #no actions = drop
            else:
                po_actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]

            pkt_out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port, data=data, actions=po_actions)
            datapath.send_msg(pkt_out)



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


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        self.remove_match_state(msg.match)

    def remove_match_state(self, match):
        for matches in self.states.values():
            print(matches)
            for m in matches:
                if ((match['dl_src'] == m['dl_src']) and 
                    (match['dl_dst'] == m['dl_dst']) and 
                    (m['in_port'] == match['in_port'])):
                        matches.remove(m)