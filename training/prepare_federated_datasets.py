import os
import pandas as pd


ATTACK_FILE = "datasets/attack_data/attack_samples_5sec.csv"
BENIGN_FILE = "datasets/benign_data/benign_samples_5sec.csv"

OUTPUT_A = "datasets/node_A_data.csv"
OUTPUT_B = "datasets/node_B_data.csv"
OUTPUT_C = "datasets/node_C_data.csv"


def main():
    print("Preparing federated edge datasets...")

    if not os.path.exists(ATTACK_FILE):
        raise FileNotFoundError(f"Missing attack file: {ATTACK_FILE}")

    if not os.path.exists(BENIGN_FILE):
        raise FileNotFoundError(f"Missing benign file: {BENIGN_FILE}")

    attack_df = pd.read_csv(ATTACK_FILE)
    benign_df = pd.read_csv(BENIGN_FILE)

    print(f"Loaded attack samples: {len(attack_df)}")
    print(f"Loaded benign samples: {len(benign_df)}")

    # Add labels if not already present
    if "label" not in attack_df.columns:
        attack_df["label"] = 1

    if "label" not in benign_df.columns:
        benign_df["label"] = 0

    # Combine
    combined = pd.concat([attack_df, benign_df], ignore_index=True)

    # Shuffle
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    total = len(combined)
    split1 = total // 3
    split2 = 2 * total // 3

    node_a = combined.iloc[:split1].copy()
    node_b = combined.iloc[split1:split2].copy()
    node_c = combined.iloc[split2:].copy()

    os.makedirs("datasets", exist_ok=True)

    node_a.to_csv(OUTPUT_A, index=False)
    node_b.to_csv(OUTPUT_B, index=False)
    node_c.to_csv(OUTPUT_C, index=False)

    print("Federated datasets created successfully:")
    print(f" - {OUTPUT_A}: {len(node_a)} rows")
    print(f" - {OUTPUT_B}: {len(node_b)} rows")
    print(f" - {OUTPUT_C}: {len(node_c)} rows")

    print("\nColumns:")
    for col in combined.columns:
        print(f" - {col}")


if __name__ == "__main__":
    main()
