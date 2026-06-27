import ctypes
import os
import sys

class LogIngestor:
    def __init__(self):
        # Dynamically compile the C code to a Shared Library if not already done
        if not os.path.exists("./libtrie.so") and not os.path.exists("./libtrie.dll"):
            print("[*] Compiling backend C algorithmic acceleration engine...")
            if sys.platform.startswith("win"):
                os.system("gcc -shared -o libtrie.dll signature_trie.c")
                lib_path = "./libtrie.dll"
            else:
                os.system("gcc -shared -fPIC -o libtrie.so signature_trie.c")
                lib_path = "./libtrie.so"
        else:
            lib_path = "./libtrie.dll" if sys.platform.startswith("win") else "./libtrie.so"

        # Load the binary library
        self.lib = ctypes.CDLL(lib_path)
        
        # Configure arguments and return types for exact C-to-Python memory mapping
        self.lib.init_trie.restype = ctypes.c_void_p
        
        self.lib.insert_signature.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        
        self.lib.search_log.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.search_log.restype = ctypes.c_char_p
        
        self.lib.free_trie.argtypes = [ctypes.c_void_p]
        
        # Allocate our C Trie on the system heap
        self.trie_root = self.lib.init_trie()
        self._load_signatures()

    def _load_signatures(self):
        # High-threat malware vectors & payloads inserted directly into C memory
        signatures = {
            "192.168.1.105": "MALICIOUS_IP_BOTNET",
            "SELECT * FROM users WHERE": "SQL_INJECTION_ATTEMPT",
            "../etc/passwd": "DIRECTORY_TRAVERSAL_EXPLOIT",
            "Authorization: Bearer null": "BROKEN_AUTHENTICATION"
        }
        for sig, threat in signatures.items():
            self.lib.insert_signature(self.trie_root, sig.encode('utf-8'), threat.encode('utf-8'))
        print(f"[+] Successfully loaded {len(signatures)} threat indicators into C memory spaces.")

    def scan_log_stream(self, raw_log_line: str):
        # Evaluate streaming log data instantly via C-Trie lookup traversal
        match = self.lib.search_log(self.trie_root, raw_log_line.encode('utf-8'))
        if match:
            return match.decode('utf-8')
        return None

    def __del__(self):
        if hasattr(self, 'lib') and self.trie_root:
            self.lib.free_trie(self.trie_root)
            print("[+] Freed C heap memory allocations successfully.")

if __name__ == "__main__":
    ingestor = LogIngestor()
    test_log = "SELECT * FROM users WHERE id = 1"
    result = ingestor.scan_log_stream(test_log)
    print(f"Test Scan Result: {result}")
