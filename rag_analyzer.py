import numpy as np
from log_ingest import LogIngestor

class LocalRAGSystem:
    def __init__(self):
        # Security Knowledge Base (Our Documents)
        self.kb = [
            {"threat": "SQL_INJECTION_ATTEMPT", "solution": "Isolate the connection parameter, deploy prepared statements immediately, and use input sanitization frameworks."},
            {"threat": "MALICIOUS_IP_BOTNET", "solution": "Update the local network firewalls and iptables to drop all incoming packets from this IP CIDR block entirely."},
            {"threat": "DIRECTORY_TRAVERSAL_EXPLOIT", "solution": "Audit file system privileges. Restrict directory access execution parameters and ensure absolute filepath canonicalization."},
            {"threat": "BROKEN_AUTHENTICATION", "solution": "Enforce strict JWT signature verification validations and implement stateless token expiration middleware."}
        ]
        # Basic vocabulary mapping to create deterministic mathematical embeddings without huge transformers
        self.vocab = list(set(" ".join([d["threat"] for d in self.kb]).lower().split()))
        self.vector_store = [self._embed(doc["threat"]) for doc in self.kb]

    def _embed(self, text: str) -> np.ndarray:
        # Simple Term Frequency Embedding Vectorizer
        tokens = text.lower().split()
        return np.array([tokens.count(word) for word in self.vocab], dtype=float)

    def _cosine_similarity(self, v1: np.ndarray, v2: np.ndarray) -> float:
        dot = np.dot(v1, v2)
        norm_a = np.linalg.norm(v1)
        norm_b = np.linalg.norm(v2)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def retrieve_context(self, matched_threat: str) -> str:
        query_vector = self._embed(matched_threat)
        best_score = -1
        best_match = None

        for idx, doc_vector in enumerate(self.vector_store):
            score = self._cosine_similarity(query_vector, doc_vector)
            if score > best_score:
                best_score = score
                best_match = self.kb[idx]
        
        return best_match["solution"] if best_match else "No playbook entry found."

    def generate_incident_response(self, log_line: str, threat_type: str):
        context = self.retrieve_context(threat_type)
        # Augmenting the generation loop
        prompt = (
            f"[SYSTEM THREAT REPORT]\n"
            f"ALERT INDICATION: Log match flagged classification as [{threat_type}].\n"
            f"VULNERABLE TELEMETRY STRINGS: '{log_line}'\n"
            f"RETRIEVED MITIGATION CONTEXT: {context}\n"
            f"------------------------------------------------------------------------\n"
            f"[AUTOMATED ACTION PLAN]:\n"
            f"Deploy immediate system state updates: '{context}' to mitigate structural vector risks."
        )
        return prompt

def main():
    print("=== STARTING LIVE THREAT DETECTION & SECTREE-RAG ANALYSIS ===")
    ingestor = LogIngestor()
    rag = LocalRAGSystem()

    # Simulating a live incoming attack stream vector
    incoming_logs = [
        "2026-06-27T22:14:02Z INF USR-REQ ip='192.168.1.105' payload='normal_ping'",
        "2026-06-27T22:15:44Z ERR SQL-CONN query='SELECT * FROM users WHERE id=1'"
    ]

    for log in incoming_logs:
        print(f"\n[Ingesting Log]: {log}")
        # Search raw data via C Trie
        detected_threat = ingestor.scan_log_stream(log)
        
        if detected_threat:
            print(f"[!] Threat Detected by C-Backend Engine: {detected_threat}")
            # Route into RAG System
            response = rag.generate_incident_response(log, detected_threat)
            print(response)
        else:
            print("[+] Log clear. No structural signatures matched.")

if __name__ == "__main__":
    main()
