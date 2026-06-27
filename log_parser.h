#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include <stdbool.h>

// Struct mapping exactly how Python's ctypes layout will interact with memory
typedef struct TrieNode TrieNode;

/**
 * @brief Allocates memory and initializes the root node of the threat Trie.
 * @return Pointer to the allocated root TrieNode.
 */
TrieNode* init_trie();

/**
 * @brief Inserts a malicious signature pattern into the Trie structure.
 * @param root Pointer to the root node.
 * @param key The payload pattern, string signature, or IP block prefix.
 * @param threat The label classification (e.g., "SQL_INJECTION", "BRUTE_FORCE").
 */
void insert_signature(TrieNode* root, const char* key, const char* threat);

/**
 * @brief Validates a line of incoming log telemetry against the Trie dictionary.
 * @return A string pointer to the threat classification context if a match hits, otherwise NULL.
 */
const char* search_log(TrieNode* root, const char* key);

/**
 * @brief Recursively traverses the structure and releases system heap memory.
 */
void free_trie(TrieNode* root);

#endif // LOG_PARSER_H
