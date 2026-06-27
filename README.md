# SecurTree-RAG: High-Performance Log Parser & AI Incident Responder

SecurTree-RAG combines a low-level C processing engine with a Python-based RAG pipeline to analyze network logs and auto-generate threat mitigation reports in real-time.

## How it Works
1. **Ingestion (C):** Raw logs are streamed into a highly optimized **Trie (Prefix Tree)** structure implemented in C, enabling $O(L)$ signature matching against 10,000+ known malicious IPs.
2. **Context Enrichment (Python):** Flagged security events are bridged via `ctypes` to Python.
3. **Retrieval-Augmentation (RAG):** The system vectorizes the anomalous log, queries an offline database of NIST/OWASP security frameworks, and uses an LLM to generate instant defensive actions.
