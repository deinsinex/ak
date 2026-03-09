from federation.client import send_weights
import time


def simulate_edge(edge_id, weights):

    print(f"\nSending weights from {edge_id}")

    if not isinstance(weights, dict):
        print("Invalid weight format.")
        return

    send_weights(weights)


if __name__ == "__main__":

    # Simulate three edge firewalls
    edge1 = {"w1": 0.5, "w2": 1.2}
    edge2 = {"w1": 0.7, "w2": 1.1}
    edge3 = {"w1": 0.6, "w2": 1.4}

    simulate_edge("EDGE_1", edge1)
    time.sleep(1)

    simulate_edge("EDGE_2", edge2)
    time.sleep(1)

    simulate_edge("EDGE_3", edge3)
