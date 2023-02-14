import requests
import copy
from mininet.cli import CLI

from mininet.link import TCLink
from mininet.log import setLogLevel, info, warn
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
import os
import json
from mininet.util import dumpNodeConnections
 
 
class SimpleTopo(Topo):
    "Simple loop topology"
 
    def __init__(self):
        "Create custom loop topo."
 
        # Initialize topology
        Topo.__init__(self)

        self.config = {}
        self.link_info = {}
        self.populateConfig()
 
        ## Add hosts 
        h1 = self.addHost("h1", mac='00:00:00:00:00:01')
        h2 = self.addHost("h2", mac='00:00:00:00:00:02')
        h3 = self.addHost("h3", mac='00:00:00:00:00:03')
        h4 = self.addHost("h4", mac='00:00:00:00:00:04')
        h5 = self.addHost("h5", mac='00:00:00:00:00:05')
        h6 = self.addHost("h6", mac='00:00:00:00:00:06')      

        ## Add switches
        s1 = self.addSwitch("s1", dpid="1")
        s2 = self.addSwitch("s2", dpid="2")
        s3 = self.addSwitch("s3", dpid="3")
        s4 = self.addSwitch("s4", dpid="4")
        s5 = self.addSwitch("s5", dpid="5")
        s6 = self.addSwitch("s6", dpid="6")

        # Add host links
        self.addLink("s1", "h1", port1 = 3, cls = TCLink, bw=1000, delay = 2)
        self.addLink("s2", "h2", port1 = 4, cls = TCLink, bw=1000, delay = 2)
        self.addLink("s3", "h3", port1 = 4, cls = TCLink, bw=1000, delay = 2)
        self.addLink("s4", "h4", port1 = 3, cls = TCLink, bw=1000, delay = 2)
        self.addLink("s5", "h5", port1 = 4, cls = TCLink, bw=1000, delay = 2)
        self.addLink("s6", "h6", port1 = 4, cls = TCLink, bw=1000, delay = 2)


        self.addLink("s1", "s2", port1 = 1, port2 = 1, cls = TCLink, bw=self.link_info["{}_{}".format(1, 2)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(1, 2)]['latency']))
        self.addLink("s1", "s6", port1 = 2, port2 = 1, cls = TCLink, bw=self.link_info["{}_{}".format(1, 6)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(1, 6)]['latency']))
        self.addLink("s2", "s3", port1 = 2, port2 = 1, cls = TCLink, bw=self.link_info["{}_{}".format(2, 3)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(2, 3)]['latency']))
        self.addLink("s2", "s5", port1 = 3, port2 = 2, cls = TCLink, bw=self.link_info["{}_{}".format(2, 5)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(2, 5)]['latency']))
        self.addLink("s3", "s4", port1 = 3, port2 = 1, cls = TCLink, bw=self.link_info["{}_{}".format(3, 4)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(3, 4)]['latency']))
        self.addLink("s3", "s6", port1 = 2, port2 = 3, cls = TCLink, bw=self.link_info["{}_{}".format(3, 6)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(3, 6)]['latency']))
        self.addLink("s4", "s5", port1 = 2, port2 = 3, cls = TCLink, bw=self.link_info["{}_{}".format(4, 5)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(4, 5)]['latency']))
        self.addLink("s5", "s6", port1 = 1, port2 = 2, cls = TCLink, bw=self.link_info["{}_{}".format(5, 6)]['bandwidth'], delay='{}ms'.format(self.link_info["{}_{}".format(5, 6)]['latency']))

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

def run_test(net, host, config_file="test-config1.json"):
    cmd = "python3 simulate_traffic.py {0} {1} > {0}out 2>&1 &"
    h = net.get(host)
    h.cmd(cmd.format(host, config_file))

def test():
    numswitches = 3
    hostsPerSwitch = 2
    should_test = False

    topo = SimpleTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)

    print("Start the Ryu manager on a seperate terminal. Press enter to continue.")
    input()

    net.addController('c0', controller=RemoteController,
            ip='127.0.0.1', port=6633)
    net.start()

    if should_test == True:
        # run_test(net, "h2", "redistribute-test-config_h1h2.json")
        # run_test(net, "h5", "redistribute-test-config_h1h2.json")

        run_test(net, "h3", "redistribute-test-config_h1h3.json")
        run_test(net, "h1", "redistribute-test-config_h1h3.json")


        # run_test(net, "h4", "redistribute-test-config_h1h4.json")
        # run_test(net, "h1", "redistribute-test-config_h1h4.json")

    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    test()
