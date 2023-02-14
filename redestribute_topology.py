import requests
import copy
from mininet.cli import CLI

from mininet.link import TCLink
from mininet.log import setLogLevel, info, warn
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
 
 
class SimpleTopo(Topo):
    "Simple loop topology"
 
    def __init__(self):
        "Create custom loop topo."
 
        # Initialize topology
        Topo.__init__(self)
 
        # Add hosts and switches
        ## Add hosts 
        h1 = self.addHost("h1", mac='00:00:00:00:00:01')
        h2 = self.addHost("h2", mac='00:00:00:00:00:02')
        h3 = self.addHost("h3", mac='00:00:00:00:00:03')
        h4 = self.addHost("h4", mac='00:00:00:00:00:04')
        h5 = self.addHost("h5", mac='00:00:00:00:00:05')       

        ## Add switches
        s1 = self.addSwitch("s1", dpid="1")
        s2 = self.addSwitch("s2", dpid="2")
        s3 = self.addSwitch("s3", dpid="3")
        s4 = self.addSwitch("s4", dpid="4")


        # Add links (Use the switches in then node1 space)
        # Link function prototye:
        ## mininet.net.Mininet.addLink( self, node1, node2, port1 = None, port2 = None, cls = None, params ) 
        self.addLink(  "s1", "h1", port1 = 1, cls = None)
        self.addLink(  "s1", "s2", port1 = 2, port2 = 1, cls = None)
        self.addLink(  "s1", "s3", port1 = 3, port2 = 1, cls = None)
        self.addLink(  "s2", "s4", port1 = 2, port2 = 1, cls = None)
        self.addLink(  "s3", "s4", port1 = 2, port2 = 2, cls = None)
        self.addLink(  "s4", "h2", port1 = 3, cls = None)
        self.addLink(  "s4", "h3", port1 = 4, cls = None)
        self.addLink(  "s2", "h5", port1 = 3, cls = None)
        self.addLink(  "s2", "h4", port1 = 4, cls = None)


def run_test(net, host, config_file="test-config1.json"):
    cmd = "python3 simulate_traffic.py {0} {1} > {0}out 2>&1 &"
    h = net.get(host)
    h.cmd(cmd.format(host, config_file))

def test():
    numswitches = 3
    hostsPerSwitch = 2

    topo = SimpleTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)

    print("Start the Ryu manager on a seperate terminal. Press enter to continue.")
    input()

    net.addController('c0', controller=RemoteController,
            ip='127.0.0.1', port=6633)
    net.start()

    # run_test(net, "h2", "test-config1.json")
    # run_test(net, "h1", "test-config1.json")

    run_test(net, "h2", "redistribute-test-config_h1h2.json")
    run_test(net, "h3", "redistribute-test-config_h1h3.json")
    run_test(net, "h4", "redistribute-test-config_h1h4.json")
    run_test(net, "h1", "redistribute-test-config_h1h2.json")
    run_test(net, "h1", "redistribute-test-config_h1h3.json")
    run_test(net, "h1", "redistribute-test-config_h1h4.json")

    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    test()

