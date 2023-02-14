import networkx as nx

G = nx.DiGraph()

G.add_node(1)
G.add_node(1)

G.add_node(2)

G.add_node(3)

G.add_edge(1, 2)
G.add_edge(1, 2)

G[1][2]['port1'] = 2
G[1][2]['port2'] = 2

G.remove_edge(1, 2)
G.remove_edge(1, 2)

print(G[1][2])

dpid = 4
a = format(dpid, "d").zfill(16)
print(a)

a = 2
b = 4

c = 4

c = 8 if a+b == 7 else c

gg = float('-inf')

print(gg)
print(-gg)

dicti = {}

dicti[4] = 2
dicti.setdefault(4, 0)
dicti[4] += 1
print(dicti)
# print(c)

# print(G.nodes)
# print(G.edges())