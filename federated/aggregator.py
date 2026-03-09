import json
import os
import numpy as np


class FederatedAggregator:

    def __init__(self):

        self.global_model = None

        if os.path.exists("federated/global_model.json"):

            with open("federated/global_model.json") as f:
                self.global_model = json.load(f)


    def aggregate(self, models):

        """
        Perform Federated Averaging (FedAvg)
        """

        print("\nAggregating models...\n")

        if not models:
            print("No models received.")
            return None

        # Collect union of all parameter keys
        keys = set()

        for model in models:
            keys.update(model.keys())

        aggregated = {}

        for key in keys:

            values = []

            for model in models:

                if key not in model:
                    continue

                try:
                    value = float(model[key])
                except Exception:
                    continue

                values.append(value)

            if values:

                # basic protection against extreme poisoning
                values = np.clip(values, -1e6, 1e6)

                aggregated[key] = float(np.mean(values))

        self.global_model = aggregated

        os.makedirs("federated", exist_ok=True)

        with open("federated/global_model.json", "w") as f:
            json.dump(aggregated, f, indent=4)

        print("Global model created.")

        return aggregated
