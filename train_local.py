from federated.edge_node import EdgeNode
from federation.client import send_weights


def train_and_send(node_id, dataset_path):

    print(f"\nStarting local training on {node_id}")

    node = EdgeNode(node_id, dataset_path)

    node.train_local_model()

    weights = node.export_weights()

    print("Sending weights to federation server...")

    send_weights(weights)

    print("Federated update sent.")


if __name__ == "__main__":

    # Example dataset path
    dataset = "datasets/attack_data/attack_samples_5sec.csv"

    train_and_send("EDGE_NODE_1", dataset)
