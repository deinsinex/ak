import re


class PayloadInspector:

    def __init__(self):

        self.signatures = [

            rb"\bbash\s+-i\b",
            rb"\bnc\s+-e\b",
            rb"\bsh\s+-i\b",
            rb"/bin/bash",
            rb"/bin/sh",

            rb";\s*ls\b",
            rb";\s*cat\b",
            rb";\s*wget\b",
            rb";\s*curl\b",

            rb"\bbase64\b",
            rb"eval\(",
            rb"exec\(",

            rb"import\s+os",
            rb"os\.system",
            rb"subprocess",

            rb"sudo\s+su",
            rb"chmod\s+777"
        ]

        self.compiled = [re.compile(sig, re.IGNORECASE) for sig in self.signatures]


    def inspect(self, payload: bytes):

        if not payload:
            return False

        try:

            payload = payload[:2000]

            for pattern in self.compiled:

                if pattern.search(payload):

                    print("\n⚠️ MALICIOUS PAYLOAD DETECTED")
                    print("Signature:", pattern.pattern)

                    return True

            return False

        except Exception as e:

            print("Payload inspection error:", e)
            return False
