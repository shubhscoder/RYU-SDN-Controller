from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp, ipv4, ipv6
import threading
import time
from threading import Lock
from ryu.lib import hub
from operator import attrgetter
import sys
from ryu.topology import event
from ryu.topology.api import get_switch, get_link, get_host

import networkx as nx
import time
import sys
import json
import os
from queue import PriorityQueue

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    cookie_mask = 0xFFFFFFFFFFFFFFFF
    broadcast = 'ff:ff:ff:ff:ff:ff'

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        # Stores the mapping between mac address and the port connected to the corresponding link.
        self.mac_to_port = {}

        # Stores the information related to bandwidth and latency, collected from config file.
        self.link_info = {}

        # List of active switches in the topology.
        self.switches = []

        # The graph that maintains the entire topology.
        self.graph = nx.DiGraph()

        # There is a delay, in discovering links, this bool is set to true, once link
        # discovery is complete.
        self.discovered_links = False

        # The map that stores all necessary configuration information read from the 
        # config file.
        self.config = {}

        # The type of routing, shortest, widest, proactive, redistribution.
        self.routing_type = 0

        # Function that reads config from the json and populates it.
        self.populateConfig()

        # An unique cookie generated for flows in the network.
        self.cookie_counter = 1

        # map to store cookie for the flow between two hosts
        # (h1, h2) : cookie_number
        self.host_pair_to_cookie_map = {}

        # Reverse map to store, the host pair, corresponding to the cookie.
        # (cookie_number) : (h1, h2)
        self.cookie_to_host_pair_map = {}

        # Time period to collect statistics.
        self.t2 = 10

        # A cache for the discovered path between a source and destination pair.
        self.src_to_dst_path_map = {}

        # A map that stores the history of number of bytes transferred between
        # a given src and dst pair.
        self.src_to_dst_history = {}

        # Maximum length for the history (In the above data structure.)
        self.m = 5

        # Lock for handling shared data, between stats thread and processing thread.
        self.lock = Lock()

        # Cookie's that were discovered in the current iteration while collecting flows.
        self.seen_cookie_per_iteration_set = {}

        # Counter to track number of outgoing requests for collecting flow stats.
        self.request_cnt = 0

        # Lock to protect the above counter.
        self.request_cnt_lock = Lock()

        # Barrier for all flow stats requests to return and get response.
        self.count_barrier = True

        # Updated bandwidth between pairs during redistribution.
        self.pair_bw_update_set = set()
        if self.routing_type == "redistribution":
            self.redistribution_thread = hub.spawn(self.redistribute)
        
        # Port data, used for proactive flow distribution.
        self.monitor_data = {}

        if self.routing_type != "shortest_path":
            self.monitor_thread = hub.spawn(self._monitor)
    
    # Redistribute flows after t2 duration.
    def redistribute(self):
        while True:
            hub.sleep(self.t2)
            # redistribution in progress
            if not self.count_barrier:
                print("Redistribution in progress. Ignoring request data.")
                continue
            self.seen_cookie_per_iteration_set.clear()
            with self.lock:
                for dp in self.switches:
                    with self.request_cnt_lock:
                        self.request_cnt += 1
                    self.request_stats(dp)
                if len(self.switches) != 0:
                    self.count_barrier = False
            
    # Update bandwidth usage between pair of hosts, during each redistribution.
    def update_bandwidths(self, path, avg_usage):
        for iter in range(1, len(path) - 2):
            node = path[iter]
            next_node = path[iter + 1]
            if (node, next_node) not in self.pair_bw_update_set:
                self.graph[node][next_node]['bw1'] = self.link_info["{}_{}".format(node, next_node)]['bandwidth']
                self.pair_bw_update_set.add((node, next_node))
            if avg_usage < self.graph[node][next_node]['bw1']:
                self.graph[node][next_node]['bw1'] -= avg_usage
            else:
                self.graph[node][next_node]['bw1'] = self.link_info["{}_{}".format(node, next_node)]['bandwidth']
    
    # Recaluclate paths between every pair of src and destination.
    def recalculate_paths(self):
        # Clear previous old paths, new paths will be calculated.
        print("Redistributing all flows")

        # Populate comm list from available flows.
        self.comm_list = []
        for key, value in self.src_to_dst_history.items():
            print(key, value)
            if self.host_pair_to_cookie_map[key] not in self.seen_cookie_per_iteration_set:
                print("cookie not found for path: ", self.host_pair_to_cookie_map[key])
                value.append(0)
                if len(value) > self.m:
                    value = value[1:]
                    self.src_to_dst_history[key] = value

            sum_of_bytes = sum(value)
            num_flows = len(value)
            avg = 0
            if num_flows > 0:
                avg = sum_of_bytes // num_flows
                avg = (avg * 8) / (1000000*self.t2)
            else:
                print("Sum, Avg zero for {} {}".format(key[0], key[1]))
            self.comm_list.append((avg, key[0], key[1]))
        
        print(len(self.comm_list))
        if len(self.comm_list) == 0:
            print("COMM_LIST is empty. returning")
            with self.lock:
                self.count_barrier = True
            return

        self.src_to_dst_path_map.clear()
        self.pair_bw_update_set.clear()

        
        # sort comm list in decreasing order of average bytes transferred.
        self.comm_list = sorted(self.comm_list, reverse = True)

        # reinitialize all weights
        link_lists = get_link(self, None)
        for link in link_lists:
            key1 = "{}_{}_{}_{}".format(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no)
            key2 = "{}_{}_{}_{}".format(link.dst.dpid, link.src.dpid, link.dst.port_no, link.src.port_no)
            lat = 10
            bw = 100
            if key1 in self.config:
                lat = self.config[key1]['latency']
                bw = self.config[key1]['bandwidth']
            elif key2 in self.config:
                lat = self.config[key2]['latency']
                bw = self.config[key2]['bandwidth']
            self.addLinkToGraph(link, lat, bw)
        
        # Calculate shortest path for each flow, update graph weights, and cache the shortest path.
        for byte_h1_h2 in self.comm_list:
            avg_bw_usage = byte_h1_h2[0]
            h1 = byte_h1_h2[1]
            h2 = byte_h1_h2[2]

            # Find the widest path between h1 and h2.
            h1_h2_path = self.widest_path(h1, h2)
            self.src_to_dst_path_map[(h1, h2)] = h1_h2_path
            print("SRC : {} DST : {} with avg bw {} PATH : {}".format(h1, h2, avg_bw_usage, h1_h2_path))

            # reduce the bw of all links on the path between h1 and h2.
            self.update_bandwidths(h1_h2_path, avg_bw_usage)

        for datapath in self.switches:
            print("Deleting all flows for ", datapath.id)
            self.delete_all_flows(datapath)
        
        with self.lock:
            self.count_barrier = True
        
        sys.stdout.flush()

    # Function that requests stats for a given switch in every iteration.
    def request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
    
    # Response handler for the async request for getting flow stats.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for flow in body:
            cookie = flow.cookie

            with self.lock:
                #ignore default or already processed flows. These flows are processed by some other switch.
                if cookie == 0 or (cookie in self.seen_cookie_per_iteration_set):
                    print("Ignoring cookie {} from {}".format(cookie, ev.msg.datapath.id))
                    continue
            prev_sum = sum(self.src_to_dst_history.get(cookie, []))
            current_byte_cnt = flow.byte_count - prev_sum
            history = self.src_to_dst_history.setdefault(self.cookie_to_host_pair_map[cookie], [])
            history.append(current_byte_cnt)
            if len(history) > self.m:
                history = history[1:]
                self.src_to_dst_history[self.cookie_to_host_pair_map[cookie]] = history
            self.seen_cookie_per_iteration_set[cookie] = cookie
                    
        with self.request_cnt_lock:
            self.request_cnt -= 1

        call_recalculate = False
        with self.request_cnt_lock:
            if self.request_cnt == 0:
                call_recalculate = True
        
        if call_recalculate:
            self.recalculate_paths()

    # Utility to populate configuration file.
    def populateConfig(self):
        __location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))
        config_file = open(os.path.join(__location__, 'topology-config2.json'))
        config_data = json.load(config_file)
        self.routing_type = config_data['routing_type']
        for link in config_data['data']:
            key = "{}_{}_{}_{}".format(link['switch1'], link['switch2'], link['input_port'], link['output_port'])
            value = {'latency': link['latency'], 'bandwidth': link['bandwidth']}
            self.config[key] = value
            self.link_info["{}_{}".format(link['switch1'], link['switch2'])] = {'latency': link['latency'], 'bandwidth': link['bandwidth']}
            self.link_info["{}_{}".format(link['switch2'], link['switch1'])] = {'latency': link['latency'], 'bandwidth': link['bandwidth']}

        self.config["monitor_time"] = config_data["monitor_time"]
        self.config["monitor_queue_length"] = config_data["monitor_queue_length"]
        print(self.config)
        print("ROUTING_TYPE: {}".format(self.routing_type))

    # monitoring thread to get port stats for proactive scheduling.
    def _monitor(self):
        while True:
            for dp in self.switches:
                self._get_stats(dp)
            hub.sleep(self.config["monitor_time"])
    
    def _add_port_stats(self, dp_id, port_id, byte_count):
        switch_map = self.monitor_data.get(dp_id, None)
        if switch_map is None:
            self.monitor_data[dp_id] = {}
        
        switch_queue = self.monitor_data[dp_id].get(port_id, None)
        if switch_queue is None:
            switch_queue = []
            self.monitor_data[dp_id][port_id] = switch_queue

        if len(switch_queue) >= self.config["monitor_queue_length"] + 1:
            switch_queue.pop(0)
        
        switch_queue.append(byte_count)
    
    # Utility to collect port stats.
    def _print_port_stats(self):
        for dp_id in self.monitor_data:
            for port_id, byte_count in self.monitor_data[dp_id].items():
                bandwidth_consumption = []
                for i in range(len(byte_count) - 1):
                    bandwidth_consumption.append((byte_count[i+1] - byte_count[i])*8/(1000000*self.config["monitor_time"]))

    # Current bandwidth between a given pair of switches. (bandwidths are continusoly updated during
    # every iteration of redistribution.) 
    def _get_current_bandwidth(self, dp_id, port_id, total_bandwidth):
        if self.monitor_data.get(dp_id, None) is None or self.monitor_data.get(dp_id).get(port_id, None) is None:
            print("No port stats available yet. Returning default value")
            return total_bandwidth
        
        byte_count = self.monitor_data[dp_id][port_id]
        bandwidth_consumption = []
        for i in range(len(byte_count) - 1):
            bandwidth_consumption.append((
                byte_count[i+1] - byte_count[i])*8/(1000000*self.config["monitor_time"]))
        
        print("Current bw consumption for switch %s and port %s is %s" %(dp_id, port_id, str(bandwidth_consumption)))
        if len(bandwidth_consumption) == 0:
            print("No port stats available yet. Returning default value")
            return total_bandwidth                                                                                                                                                                    
        
        average_bandwidth = 0
        for e in bandwidth_consumption:
            average_bandwidth += e
        average_bandwidth /= len(bandwidth_consumption)

        print("Current average bw consumption for switch %s and port %s is %s" %(dp_id, port_id, average_bandwidth))
        
        if average_bandwidth > total_bandwidth:
            print("Current switch port is congested returning default value")
            return 0
        return total_bandwidth - average_bandwidth
    
        
    def _get_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, event):
        body = event.msg.body
        dp_id = event.msg.datapath.id
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.debug('%016x %8x %8d %8d %8d %8d %8d %8d', event.msg.datapath.id, stat.port_no, stat.rx_packets, stat.rx_bytes, stat.rx_errors, \
            stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            self._add_port_stats(dp_id, stat.port_no, stat.tx_bytes)
    
    def addNodeToGraph(self, node):
        self.graph.add_node(node.dp.id)
    
    def addLinkToGraph(self, link, lat1, bw1, lat2 = None, bw2 = None):
        lat2 = lat1 if lat2 == None else lat2
        bw2 = bw1 if bw2 == None else bw2

        self.graph.add_edge(link.src.dpid, link.dst.dpid)

        self.graph[link.src.dpid][link.dst.dpid]['port1'] = link.src.port_no
        self.graph[link.src.dpid][link.dst.dpid]['port2'] = link.dst.port_no
        self.graph[link.src.dpid][link.dst.dpid]['lat1'] = lat1
        self.graph[link.src.dpid][link.dst.dpid]['lat2'] = lat2
        self.graph[link.src.dpid][link.dst.dpid]['bw1'] = bw1
        self.graph[link.src.dpid][link.dst.dpid]['bw2'] = bw2

    def widest_path(self, src, dest, proactive = False):
        pq = PriorityQueue()
        dist = {}
        parent = {}
        parent[src] = -1
        found = set()
        pq.put((float('-inf'), str(src)))

        while pq.empty() == False:
            next = pq.get() # (-inf, 4)
            cur = next[1]
            if next[1].isdigit():
                cur = int(next[1])
            # If the distance we got from pq is greater than what we already
            # have, then we can ignore this.
            if cur in found: # no
                continue
            dist[cur] = -next[0] # {4: inf, 2: 150}
            found.add(cur) # {4}

            for neighbor in self.graph.out_edges(cur):#(4,3)
                dist_to_neighbor = None
                if proactive :
                    current_bandwidth = self._get_current_bandwidth(neighbor[0], self.graph[neighbor[0]][neighbor[1]]['port1'], self.graph[neighbor[0]][neighbor[1]]['bw1'])
                    dist_to_neighbor = min(current_bandwidth, dist[cur])
                else:
                    dist_to_neighbor = min(self.graph[neighbor[0]][neighbor[1]]['bw1'] , dist[cur])# min(100, inf) = 100
                if neighbor[1] in found or parent[cur] == neighbor[1]:
                    continue
                if neighbor[1] in dist and dist[neighbor[1]] >= dist_to_neighbor:
                    continue

                dist[neighbor[1]] = dist_to_neighbor#100
                parent[neighbor[1]] = cur # {2: 4, 3:4}
                pq.put((-dist_to_neighbor, str(neighbor[1]))) # {(-100, 4)}
        
        print("BANDWIDTH OF WIDEST PATH : {}".format(dist[dest]))

        if dist[dest] <= 0 and proactive == True:
            # All paths are congested, no way to reach the source, fallback to static way
            # of routing.
            return self.widest_path(src, dest, proactive = False)
        
        path = []
        # Get path from src to dest
        if dest not in parent:
            # dest not reachable
            return path
        
        while dest in parent:
            path.append(dest)
            dest = parent[dest]

        path.reverse()
        return path
    
    def shortest_path(self, src, dest):
        pq = PriorityQueue()
        dist = {}
        parent = {}
        parent[src] = -1
        found = set()
        pq.put((0, str(src)))

        while pq.empty() == False:
            next = pq.get()
            cur = next[1]
            if next[1].isdigit():
                cur = int(next[1])
            # If the distance we got from pq is greater than what we already
            # have, then we can ignore this.
            if cur in found:
                continue
            
            dist[cur] = next[0]
            found.add(cur)

            for neighbor in self.graph.out_edges(cur):
                dist_to_neighbor = self.graph[neighbor[0]][neighbor[1]]['lat1'] + dist[cur]
                if neighbor[1] in found or parent[cur] == neighbor[1]:
                    continue
                if neighbor[1] in dist and dist[neighbor[1]] <= dist_to_neighbor:
                    continue
                
                dist[neighbor[1]] = dist_to_neighbor
                parent[neighbor[1]] = cur
                pq.put((dist_to_neighbor, str(neighbor[1])))
        
        print("LATENCY OF SHORTEST PATH : {}".format(dist[dest]))
        path = []
        # Get path from src to dest
        if dest not in parent:
            # dest not reachable
            return path
        
        while dest in parent:
            path.append(dest)
            dest = parent[dest]

        path.reverse()
        return path

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.add_defaul_flow(ev.msg.datapath)
    
    def add_defaul_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, is_default = True)

    def add_flow(self, datapath, priority, match, actions, is_default = False, buffer_id=None, cookie=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if buffer_id:
            if cookie is not None:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match,
                                        instructions=ins, cookie=cookie, cookie_mask=self.cookie_mask)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match,
                                        instructions=ins)
        else:
            if cookie is not None:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst, cookie=cookie, cookie_mask=self.cookie_mask)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def delete_all_flows(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()

        flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, 
            table_id=ofproto.OFPTT_ALL, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        datapath.send_msg(flow_mod)

        self.add_defaul_flow(datapath)
    
    #reference workshop3
    def mac_learning(self, dpid, src_mac, in_port):
        """
        If an unknown mac address is found, learn that for future packages
        :type dpip: string - name for the switch (datapath) 
        :type src_mac: string
        :type in_port: int 
        :return: if it was correctly learned 
        :rtype: Bool
        """
        # Initialize value on the dictionary
        self.mac_to_port.setdefault(dpid, {})
        #If the mac is already known
        if src_mac in self.mac_to_port[dpid]:
            #If the mac is comming from a different port that it was initiallly known
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            # Store port used for the given MAC address.
            self.mac_to_port[dpid][src_mac] = in_port
            return True

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})


        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
            self.add_flow(datapath, 1, match, actions)
            return

        # ARP Protcol
        if isinstance(arp_pkt, arp.arp):
            #avoid arp broadcast more than once
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return
        # Two possibilities:
        #    1. src is present in the graph, in this case, we don't need to do anything.
        #    2. src is not present in the graph, this is the opportunity to add it to the graph.

        cookie = 0
        if dst != self.broadcast:
            if (src, dst) in self.host_pair_to_cookie_map:
                cookie = self.host_pair_to_cookie_map[(src, dst)]
            else:
                cookie = self.cookie_counter
                self.host_pair_to_cookie_map[(src, dst)] = cookie
                self.cookie_to_host_pair_map[cookie] = (src, dst)
                self.cookie_counter += 1

        # HOST discovery
        if  src not in self.graph.nodes:
            self.graph.add_node(src)
            self.graph.add_edge(src, datapath.id)
            #TODO update lat and bw for host to switch links
            self.graph[src][datapath.id]['lat1'] = 2
            self.graph[src][datapath.id]['bw1'] = 1000
            self.graph[src][datapath.id]['port1'] = 0
            self.graph[src][datapath.id]['port2'] = in_port

            self.graph.add_edge(datapath.id, src)
            self.graph[datapath.id][src]['lat1'] = 2
            self.graph[datapath.id][src]['bw1'] = 1000
            self.graph[datapath.id][src]['port1'] = in_port
            self.graph[datapath.id][src]['port2'] = 0

        '''
        Similar to source, we have two possibilities for dst:
            1. dst is present in the graph, in this case, we can find the shortest path from 
               src to dst and add a static rule with flow mod.
            2. dst is not present in the graph, we have to flood the network.
        '''

        if dst not in self.graph.nodes:
            out_port = ofproto.OFPP_FLOOD
        else:
            # Find shortest path, decide next hop accordingly.
            # Add rule to the switch for next time.
            path = []
            path_type = self.routing_type
            if (src, dst) not in self.src_to_dst_path_map:
                if self.routing_type == "shortest_path":
                    path = self.shortest_path(src, dst)
                elif self.routing_type == "widest_path":
                    path = self.widest_path(src, dst)
                    path_type = "Widest"
                elif self.routing_type == "proactive":
                    path = self.widest_path(src, dst, True)
                    path_type = "Proactive"
                else:
                    #call fucntion
                    path = self.widest_path(src, dst, True)
                    path_type = "Redistributed"
                self.src_to_dst_path_map[(src, dst)] = path
                print("{} path from {} to {} is : {} at dp {}".format(path_type, src, dst, path, datapath.id))
            else:
                path = self.src_to_dst_path_map[(src, dst)]
            if datapath.id in path:
                next_hop = path[path.index(datapath.id) + 1]
                out_port = self.graph[datapath.id][next_hop]['port1']
            else:
                return
        sys.stdout.flush()
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        # Add a unique cookie corresponding to this src, dst pair
        # This will be used for calculating packets between the pair.
        flag = 0
        if out_port != ofproto.OFPP_FLOOD:
            flag = 1
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, cookie=cookie)
                return
            else:
                self.add_flow(datapath, 1, match, actions, cookie=cookie)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    # A function to clear all necessary states after redistribution iteration.
    def clearTempState(self):
        switch_list = get_switch(self, None)

        with self.lock:
            self.switches = []
            for switch in switch_list:
                self.switches.append(switch.dp)
                self.delete_all_flows(switch.dp)
        
        self.src_to_dst_path_map.clear()
        self.host_pair_to_cookie_map.clear()
        self.cookie_to_host_pair_map.clear()

    # Below are event handlers for all respective topology change events.
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.graph.add_node(ev.switch.dp.id)
        self.clearTempState()
    
    @set_ev_cls(event.EventSwitchReconnected, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handle_switch_reconnect(self, eve):
        self.graph.add_node(eve.switch.dp.id)
        self.clearTempState()

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handle_switch_leave(self, eve):
        self.graph.remove_node(eve.switch.dp.id)
        self.clearTempState()
    
    @set_ev_cls(event.EventLinkAdd, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handle_link_add(self, eve):
        self.addLinkToGraph(eve.link, self.link_info["{}_{}".format(eve.link.src.dpid, eve.link.dst.dpid)]['latency'], self.link_info["{}_{}".format(eve.link.src.dpid, eve.link.dst.dpid)]['bandwidth'])
        self.clearTempState()
    
    @set_ev_cls(event.EventLinkDelete, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handle_link_delete(self, eve):
        try:
            self.graph.remove_edge(eve.link.src.dpid, eve.link.dst.dpid)
        except Exception as e:
            print(e)
        self.clearTempState()

    @set_ev_cls(event.EventHostAdd, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handle_host_addition(self, eve):
        hosts = get_host(self)

