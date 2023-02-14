# RYU-SDN-Controller

# Expected Outcome
We have implemented a set of OpenFlow rules that can adapt to network topologies changes and to traffic changes. Additionally, to be able to tests this rules, we have implemented a host service in which we can control the traffic going in and out of that service.

# Sections of the Project

## Monitor

This code is for being able to debug and understand what the network is doing. More specifically this code should prints periodically, with period T1, the following information:
* Port stats
* Flow stats

## Topology Discovery

This code Creates a graph of the topology that Ryu application is going to be controlling. This topology adapts to changes in the topology when switches go up or down. The graphs are created using the networkx library. You need to use the flag "—observe-links" when running the Ryu Controller, to be able to see the changes. Given that the Ryu Controller cannot detect the bandwidth and latencies of the connected links. We therefore read this configuration from the json.

## How we test our code?

We can test this code section by using the following mininet commands:

```c
link <node1> <node2> down: takes down the link between node1 and node2.

link <node1> <node2> up: brings up the link between node1 and node2.

<node1> and <node2> could be either switches or hosts.
```

## Flow distribution strategies

### Shortest path

The Ryu application  uses the topology graph created in the Topology module to create rules that implement the shortest path. The corresponding handler (PacketIn) installs entries that match packets based on the destination MAC address and Ethernet type. The switch sends the packet through a port that is connected to a path that is the shortest path to the destination.

* If multiple paths have the same length, we choose the next hop randomly.
* Our Ryu application handle's loops in the topologies.
* Each time the shortest path is found, corresponding rules are installed in all the switches in the path.

### Widest-path

Similar to the shortest-path, the Ryu application  uses the topology graph created in the Topology module to create rules that implement the widest path. The corresponding handler (PacketIn) needs to install entries that match packets based on the destination MAC address and Ethernet type. The switch sends the packet through a port that is connected to a path that is the widest path to the destination.

* The widest-path is determined by the bandwidth of the links.
* If multiple paths have the same bandwidth, we choose the next hop randomly.
* The  Ryu application handle's loops in the topologies.
* Each time the widest path is found, corresponding rules are installed in all the switches in the path.
* We use a variation of Djikstra's algorithm

### Proactive Rule

The rules described previously are calculated once and don’t take into account statistics of network usage as the ones obtained in the Monitoring section. We use additional logic to the Widest-path controller to be able to adapt based on changes in the network. For each flow in the network, we maintain a list that contains the bandwidth that had been used, as captured by the Monitor module. Each time a new flow needs to be installed (PacketIn event), we subtract the average of the list for each link from the total bandwidth available at each link in the original graph, and calculate the next hop using the highest width available path. If the host seems unreachable we fall back to the static rules.

### Redistribute

Additionally, every T2 seconds we redistribute the flow. The con-troller maintains the information related to the bytes sent between two hosts (src,dst,bytes), called comm_list. 

Using this information the controller implements the following scheme:

* Initialize the topology graph with the default bandwidth values.
* Initialize the list of rules to be installed to empty.
* Sort the comm_list from more packets to fewer packets sent.
* For each element in comm_list:
  - Find the widest path and add the required rules to the list of rules to be installed.
  - Reduce the corresponding links of the topology graph with the current average of bytes sent for the given (src,dst,packet) tuple.
* Apply all the generated rules

T2 is also an input parameter of the controller.

## Installation Dependencies

1. Networkx for python3.8
2. Run setup.sh script provided in the repository.

## Steps to run

Run the topology creator using the following command

```c
sudo mn -c && sudo python large_topo.py
```

Run the following command to start the controller.

```c
sudo ./bin/ryu-manager --observe-links ryu/app/topo_discovery.py
```

## Code

* The main controller code is in topo_discovery.py
* The topology creating code is in large_topo.py
* The json's consist of configuration for setting up flows between the host pairs.
