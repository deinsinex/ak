from federated.edge_node import EdgeNode
from federated.aggregator import FederatedAggregator
from federation.client import send_weights


def run_real_federated_simulation():
    print("\nStarting REAL Federated Learning Simulation\n")

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
    print("\nExporting local model weights...\n")
    w1 = node1.export_weights()
    w2 = node2.export_weights()
    w3 = node3.export_weights()

    # Save offline aggregated model too (local simulation artifact)
    aggregator = FederatedAggregator()
    aggregator.aggregate([w1, w2, w3])

    # Send secure federated updates to live HTTPS server
    print("\nSending secure federated updates to server...\n")

    print("[factory_A] Sending weights...")
    send_weights(w1)

    print("[factory_B] Sending weights...")
    send_weights(w2)

    print("[factory_C] Sending weights...")
    send_weights(w3)

    print("\nREAL Federated Learning Simulation Complete\n")
    print("Check: https://127.0.0.1:8000/global_model")


if __name__ == "__main__":
    run_real_federated_simulation()
