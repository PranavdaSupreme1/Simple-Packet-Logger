from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp, ipv6, icmpv6
from ryu.ofproto import ofproto_v1_3
import datetime
from collections import defaultdict


class PacketLogger(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(dict)

    # Install rule to send packets to controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        # Learn MAC
        if src != "ff:ff:ff:ff:ff:ff":
            self.mac_to_port[dpid][src] = in_port

        # Extract protocols
        ip = pkt.get_protocol(ipv4.ipv4)
        ip6 = pkt.get_protocol(ipv6.ipv6)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        arp_pkt = pkt.get_protocol(arp.arp)

        if ip:
            src_ip, dst_ip = ip.src, ip.dst
        elif ip6:
            src_ip, dst_ip = ip6.src, ip6.dst
        elif arp_pkt:
            src_ip, dst_ip = arp_pkt.src_ip, arp_pkt.dst_ip
        else:
            src_ip, dst_ip = "N/A", "N/A"

        # Protocol detection (simple)
        protocol = "OTHER"
        extra = ""

        if arp_pkt:
            protocol = "ARP"
        elif ip6:
            protocol = "IPv6"
        elif tcp_pkt:
            protocol = "TCP"
            extra = f"{tcp_pkt.src_port}->{tcp_pkt.dst_port}"
        elif udp_pkt:
            protocol = "UDP"
            extra = f"{udp_pkt.src_port}->{udp_pkt.dst_port}"
        elif icmp_pkt:
            protocol = "ICMP"

        # Logging
        time = datetime.datetime.now().strftime("%H:%M:%S")
        log_msg = (
            f"[{time}] {src_ip} → {dst_ip} | {protocol} {extra} | "
            f"{src} → {dst}"
        )

        print(log_msg)

        with open("packet_log.txt", "a") as f:
            f.write(log_msg + "\n")

        # Forwarding (learning switch)
        out_port = self.mac_to_port[dpid].get(dst)

        if out_port and out_port != in_port:
            actions = [parser.OFPActionOutput(out_port)]
        else:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
