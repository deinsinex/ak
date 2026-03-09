from federated.edge_node import EdgeNode
from federated.aggregator import FederatedAggregator


print("\nStarting Federated Learning Simulation\n")


# Simulate three factories with local datasets

node1 = EdgeNode("factory_A", "datasets/node_A_data.csv")
node2 = EdgeNode("factory_B", "datasets/node_B_data.csv")
node3 = EdgeNode("factory_C", "datasets/node_C_data.csv")


# Train local models

print("\nTraining local models...\n")

node1.train_local_model()
node2.train_local_model()
node3.train_local_model()


# Export model weights

print("\nExporting weights...\n")

w1 = node1.export_weights()
w2 = node2.export_weights()
w3 = node3.export_weights()


# Federated aggregation

aggregator = FederatedAggregator()

global_model = aggregator.aggregate([w1, w2, w3])


print("\nFederated Global Model Created:\n")

print(global_model)
