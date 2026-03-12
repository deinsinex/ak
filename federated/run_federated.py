from federated.edge_node import EdgeNode
from federation.client import send_weights


print("\nStarting REAL Federated Learning Simulation\n")


# =============================
# REAL EDGE NODES
# =============================

node1 = EdgeNode("factory_A", "datasets/node_A_data.csv")
node2 = EdgeNode("factory_B", "datasets/node_B_data.csv")
node3 = EdgeNode("factory_C", "datasets/node_C_data.csv")


# =============================
# TRAIN LOCAL MODELS
# =============================

print("\nTraining local models...\n")

node1.train_local_model()
node2.train_local_model()
node3.train_local_model()


# =============================
# EXPORT LOCAL WEIGHTS
# =============================

print("\nExporting local model weights...\n")

w1 = node1.export_weights()
w2 = node2.export_weights()
w3 = node3.export_weights()


# =============================
# SEND TO REAL SECURE SERVER
# =============================

print("\nSending secure federated updates to server...\n")

print("[factory_A] Sending weights...")
send_weights(w1)

print("[factory_B] Sending weights...")
send_weights(w2)

print("[factory_C] Sending weights...")
send_weights(w3)


print("\nREAL Federated Learning Simulation Complete\n")
print("Check: https://127.0.0.1:8000/global_model\n")
