#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define ALPHABET_SIZE 256 // Handle all ASCII characters for flexible log matching

typedef struct TrieNode {
    struct TrieNode* children[ALPHABET_SIZE];
    bool is_end_of_word;
    char threat_type[64]; // Stores metadata about the signature
} TrieNode;

// Helper to create a new node
TrieNode* create_node() {
    TrieNode* node = (TrieNode*)malloc(sizeof(TrieNode));
    if (node) {
        node->is_end_of_word = false;
        memset(node->threat_type, 0, sizeof(node->threat_type));
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            node->children[i] = NULL;
        }
    }
    return node;
}

// Exported C functions for Python ctypes integration
#ifdef _WIN32
    __declspec(dllexport) TrieNode* init_trie();
    __declspec(dllexport) void insert_signature(TrieNode* root, const char* key, const char* threat);
    __declspec(dllexport) const char* search_log(TrieNode* root, const char* key);
    __declspec(dllexport) void free_trie(TrieNode* root);
#endif

TrieNode* init_trie() {
    return create_node();
}

void insert_signature(TrieNode* root, const char* key, const char* threat) {
    TrieNode* crawl = root;
    int length = strlen(key);
    
    for (int level = 0; level < length; level++) {
        unsigned char index = (unsigned char)key[level];
        if (!crawl->children[index]) {
            crawl->children[index] = create_node();
        }
        crawl = crawl->children[index];
    }
    crawl->is_end_of_word = true;
    strncpy(crawl->threat_type, threat, sizeof(crawl->threat_type) - 1);
}

// Scans an entire log string to check if any known malicious prefix/substring matches
const char* search_log(TrieNode* root, const char* key) {
    TrieNode* crawl = root;
    int length = strlen(key);
    
    for (int level = 0; level < length; level++) {
        unsigned char index = (unsigned char)key[level];
        if (!crawl->children[index]) {
            return NULL; // Path broken, no malicious signature matched
        }
        crawl = crawl->children[index];
        if (crawl->is_end_of_word) {
            return crawl->threat_type; // Match found!
        }
    }
    return NULL;
}

// Recursive memory cleanup
void free_trie(TrieNode* root) {
    if (!root) return;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        if (root->children[i]) {
            free_trie(root->children[i]);
        }
    }
    free(root);
}
