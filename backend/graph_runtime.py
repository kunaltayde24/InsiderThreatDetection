import networkx as nx

G = nx.Graph()

def update_graph(user, entity, risk):
    G.add_edge(user, entity, weight=risk)

def get_risky_subgraph(threshold=60):
    return [(u,v,d) for u,v,d in G.edges(data=True) if d["weight"] > threshold]
