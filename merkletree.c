/*
 * merkletree.c
 * A simple implementation of Merkle Trees in C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <time.h>
#include <sys/time.h>

#define DEFAULT_BUFFER_SIZE (1024 * 1024) /* 1 MB */
#define HASH_SIZE 32                      /* SHA3-256 produces 32-byte hashes */
#define BLOCK_SIZE (16 * 1024)            /* 16 KB for each node, 16KB hits the sweet spot between
                                             I/O troughtput and number of reads/writes  */

/* Structure to store proof data */
struct merkle_proof {
  unsigned char **leaf_hashes;        /* All leaf node hashes */
  size_t leaf_count;                  /* Number of leaf nodes */
  unsigned char root_hash[HASH_SIZE]; /* Root hash */
  size_t original_size;               /* Original data size */
};

struct arguments {
  char *filename;                     /* --file FILE */
  char *data;                         /* positional argument (string) */
  int debug;                          /* --debug flag */
  int generate_proof;                 /* --proof flag */
  char *verify_proof;                 /* --verify PROOF_FILE */
};

/* Timing utilities */
struct timespec start_time, end_time;

void start_timer() {
  clock_gettime(CLOCK_MONOTONIC, &start_time);
}

double end_timer() {
  clock_gettime(CLOCK_MONOTONIC, &end_time);
  return (end_time.tv_sec - start_time.tv_sec) + 
         (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
}

/* argp parser options */
static struct argp_option options[] = {
  {"file", 'f', "FILE", 0, "Read input from file.", 0},
  {"debug", 'd', 0, 0, "Enable detailed debug output.", 0},
  {"proof", 'p', 0, 0, "Generate proof file for verification.", 0},
  {"verify", 'v', "PROOF_FILE", 0, "Verify data against existing proof file.", 0},
  {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
    case 'f':
      arguments->filename = arg;
      break;

    case 'd':
      arguments->debug = 1;
      break;

    case 'p':
      arguments->generate_proof = 1;
      break;

    case 'v':
      arguments->verify_proof = arg;
      break;

    case ARGP_KEY_ARG:
      if (arguments->data != NULL) {
        /* positional argument */
        argp_usage(state);
      }
      arguments->data = arg;
      break;

    case ARGP_KEY_END:
      /* If no input source specified, check if stdin is a pipe */
      if (!arguments->filename && !arguments->data && !arguments->verify_proof && isatty(fileno(stdin))) {
        argp_error(state, "No input provided. Use --file, positional arguments or pipe input.");
      }
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {
  options,
  parse_opt,
  "DATA",
  "Generate Merkle Tree of the input data.\n"
  "\nExamples:\n"
  "  merkletree \"hello world\"                     # Hash string\n"
  "  merkletree -f myfile.txt                       # Hash file\n"
  "  cat data.bin | merkletree                      # Hash from stdin\n"
  "  merkletree -d \"test\"                         # Debug mode\n"
  "  merkletree -p -f myfile.txt                    # Generate proof\n"
  "  merkletree -v proof_abc123.json -f myfile.txt  # Verify against proof", /* doc */
  NULL,
  NULL,
  NULL
};

/* Debug function to print hash in hex */
void debug_print_hash(const char *label, const unsigned char *hash, int debug_enabled) {
  if (!debug_enabled) return;
  
  printf("[DEBUG] %s: ", label);
  for (int i = 0; i < HASH_SIZE; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
}

/* Debug function to print tree structure */
void debug_print_tree_level(unsigned char **hashes, size_t count, int level, int debug_enabled) {
  if (!debug_enabled) return;
  
  printf("[DEBUG] Tree Level %d (%zu nodes):\n", level, count);
  for (size_t i = 0; i < count; i++) {
    printf("[DEBUG]   Node %zu: ", i);
    for (int j = 0; j < 8; j++) { // Print first 8 bytes only for readability
      printf("%02x", hashes[i][j]);
    }
    printf("...\n");
  }
  printf("\n");
}

/*
 * Compute SHA3-256 (Keccak-256 standard) hash of the input data.
 *
 * Parameters:
 *   data - pointer to input bytes to hash
 *   len  - length of input data in bytes
 *   out  - buffer (at least 32 bytes) to store the resulting hash
 */
void keccak_256(const unsigned char *data, size_t len, unsigned char *out) {
  /* Create a new message digest context */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  /* Initialize the digest context to use SHA3-256 */
  EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);

  /* Provide the input data to the digest */
  EVP_DigestUpdate(mdctx, data, len);

  /* Finalize the digest and store the hash in 'out' */
  EVP_DigestFinal_ex(mdctx, out, NULL);

  /* Free the digest context to avoid memory leaks */
  EVP_MD_CTX_free(mdctx);
}

/*
 * Splits the input buffer into fixed-size BLOCK_SIZE chunks
 * and computes sha3-256 hash for each chunk.
 * The resulting hashes are written to out_hashes array.
 *
 * Parameters:
 *    buffer     - pointer to the input data
 *    total_size - size of the input data in bytes
 *    out_hashes - dynamically allocated array to store output hashes
 *    debug      - enable debug output
 *
 * Returns:
 *    The number of chunks (leaf nodes) hashed.
 */
size_t chunk_and_hash(const unsigned char *buffer, size_t total_size, unsigned char **out_hashes, int debug) {
  size_t num_chunks = (total_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

  if (debug) {
    printf("[DEBUG] Input size: %zu bytes\n", total_size);
    printf("[DEBUG] Block size: %d bytes\n", BLOCK_SIZE);
    printf("[DEBUG] Number of chunks: %zu\n", num_chunks);
    printf("[DEBUG] Chunking and hashing data...\n");
  }

  start_timer();
  for (size_t i = 0; i < num_chunks; i++) {
    size_t offset = i * BLOCK_SIZE;
    size_t chunk_len = (offset + BLOCK_SIZE <= total_size) ? BLOCK_SIZE : (total_size - offset);
    
    if (debug) {
      printf("[DEBUG] Chunk %zu: offset=%zu, length=%zu\n", i, offset, chunk_len);
    }
    
    keccak_256(buffer + offset, chunk_len, out_hashes[i]);
    
    if (debug && i < 3) { // Show first 3 chunk hashes
      debug_print_hash("Chunk hash", out_hashes[i], debug);
    }
  }
  double chunking_time = end_timer();

  if (debug) {
    printf("[DEBUG] Chunking and hashing completed in %.6f seconds\n", chunking_time);
    printf("[DEBUG] Hashing rate: %.2f MB/s\n", (total_size / (1024.0 * 1024.0)) / chunking_time);
  }

  return num_chunks;
}

/*
 * Computes the SHA3-256 hash of the concatenation of
 * two child hashes (left and right).
 * Used to create the parent node.
 *
 * Parameters:
 *    left  - pointer to the left hash
 *    right - pointer to the right hash
 *    out   - pointer to store the resulting parent hash
 *
 * Note - If the number of nodes are odd, duplicate it.
 */
void hash_pair(const unsigned char *left, const unsigned char *right, unsigned char *out) {
  unsigned char concat[HASH_SIZE * 2];
  memcpy(concat, left, HASH_SIZE);
  memcpy(concat + HASH_SIZE, right, HASH_SIZE);
  keccak_256(concat, HASH_SIZE * 2, out);
}

/*
 * Builds the Merkle Tree from the bottom up
 * using the array of leaf hashes. This function
 * repeatedly hashes pairs of nodes until only
 * the root remains. The root hash is stored in
 * hashes[0]
 *
 * Parameters:
 *    hashes - dynamically allocated array of hashes, stores the intermediate
 *             and final Merkle Root
 *    count  - Initial number of leaf hashes
 *             (returned by chunk_and_hash)
 *    debug  - enable debug output
 */
void build_merkle_tree(unsigned char **hashes, size_t count, int debug) {
  if (debug) {
    printf("[DEBUG] Building Merkle tree from %zu leaf nodes...\n", count);
  }

  int level = 0;
  start_timer();
  
  while (count > 1) {
    if (debug) {
      debug_print_tree_level(hashes, count, level, debug);
    }

    size_t i, j = 0;
    for (i = 0; i < count; i += 2) {
      if (i + 1 < count) {
        if (debug && j < 3) { // Show first 3 hash operations per level
          printf("[DEBUG] Level %d: Hashing pair %zu (nodes %zu + %zu)\n", level, j, i, i+1);
        }
        hash_pair(hashes[i], hashes[i + 1], hashes[j]);
      } else {
        /* Duplicating the last node if the
         * number of nodes are odd */
        if (debug) {
          printf("[DEBUG] Level %d: Duplicating odd node %zu\n", level, i);
        }
        hash_pair(hashes[i], hashes[i], hashes[j]);
      }
      j++;
    }
    count = j;
    level++;
    
    if (debug) {
      printf("[DEBUG] Level %d completed, %zu nodes remaining\n", level-1, count);
    }
  }
  
  double tree_time = end_timer();
  
  if (debug) {
    printf("[DEBUG] Merkle tree construction completed in %.6f seconds\n", tree_time);
    printf("[DEBUG] Tree depth: %d levels\n", level);
    debug_print_hash("Final Merkle Root", hashes[0], debug);
  }
}

/*
 * Allocate memory for hash storage based on input size
 *
 * Parameters:
 *    input_size - size of input data in bytes
 *    debug      - enable debug output
 *
 * Returns:
 *    Pointer to allocated hash array, or NULL on failure
 */
unsigned char** allocate_hash_storage(size_t input_size, int debug) {
  size_t num_blocks = (input_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

  if (num_blocks == 0) {
    num_blocks = 1; // Handle empty input case
  }

  if (debug) {
    printf("[DEBUG] Allocating storage for %zu hash blocks\n", num_blocks);
    printf("[DEBUG] Total hash memory: %zu bytes\n", num_blocks * HASH_SIZE);
  }

  /* Allocate array of pointers */
  unsigned char **hashes = malloc(num_blocks * sizeof(unsigned char*));
  if (!hashes) {
    return NULL;
  }

  /* Allocate memory for all hashes in one contiguous block */
  unsigned char *hash_data = malloc(num_blocks * HASH_SIZE);
  if (!hash_data) {
    free(hashes);
    return NULL;
  }

  /* Set up pointers to point into the contiguous block */
  for (size_t i = 0; i < num_blocks; i++) {
    hashes[i] = hash_data + (i * HASH_SIZE);
  }

  return hashes;
}

/*
 * Free dynamically allocated hash storage
 *
 * Parameters:
 *    hashes - pointer to hash array returned by allocate_hash_storage
 */
void free_hash_storage(unsigned char **hashes) {
  if (hashes) {
    /* Free the contiguous hash data block */
    free(hashes[0]);
    /* Free the array of pointers */
    free(hashes);
  }
}

/* Read all input from a FILE* into a dynamically allocated buffer.
 *
  * Parameters:
 *    fp      - input stream (stdin or file)
 *    buf     - pointer to store allocated buffer
 *    buf_len - pointer to store the number of bytes read
 *    debug   - enable debug output
 *
 * Returns:
 *    0 on success, -1 on error
 */
int read_input(FILE *fp, unsigned char **buf, size_t *len, int debug) {
  size_t capacity = DEFAULT_BUFFER_SIZE;
  *buf = malloc(capacity);
  if (!*buf) return -1;

  if (debug) {
    printf("[DEBUG] Reading input, initial buffer capacity: %zu bytes\n", capacity);
  }

  size_t total = 0;
  int realloc_count = 0;
  
  start_timer();
  while (1) {
    if (total == capacity) {
      capacity *= 2;
      realloc_count++;
      if (debug) {
        printf("[DEBUG] Buffer full, reallocating to %zu bytes (realloc #%d)\n", capacity, realloc_count);
      }
      unsigned char *tmp = realloc(*buf, capacity);
      if (!tmp) {
        free(*buf);
        return -1;
      }
      *buf = tmp;
    }

    size_t read_bytes = fread(*buf + total, 1, capacity - total, fp);
    total += read_bytes;

    if (read_bytes == 0) break; // EOF or error
  }
  double read_time = end_timer();
  
  *len = total;
  
  if (debug) {
    printf("[DEBUG] Input reading completed: %zu bytes in %.6f seconds\n", total, read_time);
    printf("[DEBUG] Read rate: %.2f MB/s\n", (total / (1024.0 * 1024.0)) / read_time);
    printf("[DEBUG] Buffer reallocations: %d\n", realloc_count);
  }
  
  return 0;
}

/*
 * Converts a binary hash to its hexadecimal string representation.
 * Each byte is converted to two hex characters.
 *
 * Parameters:
 *   hash    - pointer to the binary hash data
 *   hex_str - output buffer (must be at least HASH_SIZE*2+1 bytes)
 */
void hash_to_hex(const unsigned char *hash, char *hex_str) {
  for (int i = 0; i < HASH_SIZE; i++) {
    sprintf(hex_str + i * 2, "%02x", hash[i]);
  }
  hex_str[HASH_SIZE * 2] = '\0';
}

/*
 * Converts a hexadecimal string back to binary hash format.
 * Validates that the hex string is exactly the right length.
 *
 * Parameters:
 *   hex_str - input hexadecimal string
 *   hash    - output buffer for binary hash (must be HASH_SIZE bytes)
 *
 * Returns:
 *   0 on success, -1 on invalid input format
 */
int hex_to_hash(const char *hex_str, unsigned char *hash) {
  if (strlen(hex_str) != HASH_SIZE * 2) {
    return -1;
  }
  
  for (int i = 0; i < HASH_SIZE; i++) {
    if (sscanf(hex_str + i * 2, "%2hhx", &hash[i]) != 1) {
      return -1;
    }
  }
  return 0;
}

/*
 * Generates a unique filename for the proof file based on the root hash.
 * Uses the first 3 and last 3 hex characters of the hash for uniqueness.
 *
 * Parameters:
 *   root_hash - the Merkle root hash
 *   filename  - output buffer for the generated filename
 */
void generate_proof_filename(const unsigned char *root_hash, char *filename) {
  char hex_str[HASH_SIZE * 2 + 1];
  hash_to_hex(root_hash, hex_str);
  
  sprintf(filename, "proof_%c%c%c%c%c%c.json", 
          hex_str[0], hex_str[1], hex_str[2],
          hex_str[HASH_SIZE * 2 - 3], hex_str[HASH_SIZE * 2 - 2], hex_str[HASH_SIZE * 2 - 1]);
}


/*
 * Saves the Merkle proof to a JSON file for later verification.
 * The proof includes metadata, root hash, and all leaf hashes.
 *
 * Parameters:
 *   proof - pointer to the merkle_proof structure to save
 *   debug - enable debug output
 *
 * Returns:
 *   0 on success, -1 on file creation failure
 */
int save_proof(const struct merkle_proof *proof, int debug) {
  char filename[256];
  generate_proof_filename(proof->root_hash, filename);
  
  FILE *fp = fopen(filename, "w");
  if (!fp) {
    fprintf(stderr, "Failed to create proof file: %s\n", filename);
    return -1;
  }
  
  if (debug) {
    printf("[DEBUG] Saving proof to file: %s\n", filename);
  }
  
  fprintf(fp, "{\n");
  fprintf(fp, "  \"version\": \"1.0\",\n");
  fprintf(fp, "  \"block_size\": %d,\n", BLOCK_SIZE);
  fprintf(fp, "  \"hash_algorithm\": \"SHA3-256\",\n");
  fprintf(fp, "  \"original_size\": %zu,\n", proof->original_size);
  fprintf(fp, "  \"leaf_count\": %zu,\n", proof->leaf_count);
  
  char hex_str[HASH_SIZE * 2 + 1];
  hash_to_hex(proof->root_hash, hex_str);
  fprintf(fp, "  \"root_hash\": \"%s\",\n", hex_str);
  
  fprintf(fp, "  \"leaf_hashes\": [\n");
  for (size_t i = 0; i < proof->leaf_count; i++) {
    hash_to_hex(proof->leaf_hashes[i], hex_str);
    fprintf(fp, "    \"%s\"%s\n", hex_str, (i < proof->leaf_count - 1) ? "," : "");
  }
  fprintf(fp, "  ]\n");
  fprintf(fp, "}\n");
  
  fclose(fp);
  
  printf("Proof saved to: %s\n", filename);
  return 0;
}

/*
 * Loads a Merkle proof from a JSON file for verification purposes.
 * Parses the JSON structure and reconstructs the proof data.
 *
 * Parameters:
 *   filename - path to the proof JSON file
 *   debug    - enable debug output
 *
 * Returns:
 *   Pointer to loaded merkle_proof structure, or NULL on failure
 */
struct merkle_proof* load_proof(const char *filename, int debug) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "Failed to open proof file: %s\n", filename);
    return NULL;
  }
  
  if (debug) {
    printf("[DEBUG] Loading proof from file: %s\n", filename);
  }
  
  struct merkle_proof *proof = malloc(sizeof(struct merkle_proof));
  if (!proof) {
    fclose(fp);
    return NULL;
  }
  
  char line[1024];
  char hex_str[HASH_SIZE * 2 + 1];
  int parsing_hashes = 0;
  size_t hash_index = 0;
  
  proof->leaf_hashes = NULL;
  proof->leaf_count = 0;
  
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "\"original_size\"")) {
      sscanf(line, "  \"original_size\": %zu,", &proof->original_size);
    } else if (strstr(line, "\"leaf_count\"")) {
      sscanf(line, "  \"leaf_count\": %zu,", &proof->leaf_count);
      /* Allocate memory for leaf hashes */
      proof->leaf_hashes = allocate_hash_storage(proof->original_size, debug);
      if (!proof->leaf_hashes) {
        free(proof);
        fclose(fp);
        return NULL;
      }
    } else if (strstr(line, "\"root_hash\"")) {
      char *start = strstr(line, ": \"");
      if (start) {
        start += 3; /* Skip past ': "' */
        char *end = strchr(start, '"');
        if (end && (end - start) == HASH_SIZE * 2) {
          strncpy(hex_str, start, HASH_SIZE * 2);
          hex_str[HASH_SIZE * 2] = '\0';
          if (hex_to_hash(hex_str, proof->root_hash) != 0) {
            fprintf(stderr, "Failed to parse root hash\n");
          } else if (debug) {
            printf("[DEBUG] Loaded root hash: %s\n", hex_str);
          }
        }
      }
    } else if (strstr(line, "\"leaf_hashes\"")) {
      parsing_hashes = 1;
    } else if (parsing_hashes && strstr(line, "\"")) {
      char *start = strchr(line, '"') + 1;
      char *end = strchr(start, '"');
      if (end) {
        *end = '\0';
        if (strlen(start) == HASH_SIZE * 2) {
          hex_to_hash(start, proof->leaf_hashes[hash_index]);
          hash_index++;
        }
      }
    }
  }
  
  fclose(fp);
  
  if (debug) {
    printf("[DEBUG] Loaded proof: %zu leaf hashes, original size %zu bytes\n", 
           proof->leaf_count, proof->original_size);
  }
  
  return proof;
}

/*
 * Frees all memory allocated for a merkle_proof structure.
 * Properly deallocates both the hash array and the structure itself.
 *
 * Parameters:
 *   proof - pointer to the merkle_proof structure to free
 */
void free_proof(struct merkle_proof *proof) {
  if (proof) {
    if (proof->leaf_hashes) {
      free_hash_storage(proof->leaf_hashes);
    }
    free(proof);
  }
}

/*
 * Verifies current data against a previously saved proof.
 * Computes current hashes and compares them with the proof,
 * identifying specific blocks that have been modified.
 *
 * Parameters:
 *   data     - pointer to current data to verify
 *   data_len - length of current data in bytes
 *   proof    - pointer to the proof structure for comparison
 *   debug    - enable debug output
 *
 * Returns:
 *   0 if verification passes, -1 if data has been modified
 */
int verify_data_with_proof(const unsigned char *data, size_t data_len, 
                          const struct merkle_proof *proof, int debug) {
  if (debug) {
    printf("[DEBUG] === Starting Data Verification ===\n");
    printf("[DEBUG] Current data size: %zu bytes\n", data_len);
    printf("[DEBUG] Original data size: %zu bytes\n", proof->original_size);
  }
  
  /* Check if data size matches */
  if (data_len != proof->original_size) {
    printf("VERIFICATION FAILED: Data size mismatch\n");
    printf("  Expected: %zu bytes\n", proof->original_size);
    printf("  Actual: %zu bytes\n", data_len);
    return -1;
  }
  
  /* Generate current leaf hashes */
  unsigned char **current_hashes = allocate_hash_storage(data_len, debug);
  if (!current_hashes) {
    fprintf(stderr, "Failed to allocate memory for verification\n");
    return -1;
  }
  
  size_t current_leaf_count = chunk_and_hash(data, data_len, current_hashes, debug);
  
  if (current_leaf_count != proof->leaf_count) {
    printf("VERIFICATION FAILED: Leaf count mismatch\n");
    printf("  Expected: %zu leaves\n", proof->leaf_count);
    printf("  Actual: %zu leaves\n", current_leaf_count);
    free_hash_storage(current_hashes);
    return -1;
  }
  
  /* Compare leaf hashes and identify differences */
  int differences_found = 0;
  for (size_t i = 0; i < current_leaf_count; i++) {
    if (memcmp(current_hashes[i], proof->leaf_hashes[i], HASH_SIZE) != 0) {
      if (!differences_found) {
        printf("VERIFICATION FAILED: Data modifications detected\n");
        printf("\nModified blocks:\n");
        differences_found = 1;
      }
      
      size_t block_start = i * BLOCK_SIZE;
      size_t block_end = (block_start + BLOCK_SIZE <= data_len) ? 
                         (block_start + BLOCK_SIZE - 1) : (data_len - 1);
      
      printf("  Block %zu: bytes %zu-%zu\n", i, block_start, block_end);
      
      if (debug) {
        printf("    Expected hash: ");
        for (int j = 0; j < HASH_SIZE; j++) {
          printf("%02x", proof->leaf_hashes[i][j]);
        }
        printf("\n");
        
        printf("    Actual hash:   ");
        for (int j = 0; j < HASH_SIZE; j++) {
          printf("%02x", current_hashes[i][j]);
        }
        printf("\n");
      }
    }
  }
  
  if (!differences_found) {
    /* Create a separate copy of hashes for root calculation */
    unsigned char **root_hashes = allocate_hash_storage(data_len, debug);
    if (!root_hashes) {
      fprintf(stderr, "Failed to allocate memory for root calculation\n");
      free_hash_storage(current_hashes);
      return -1;
    }
    
    /* Copy leaf hashes for root calculation */
    for (size_t i = 0; i < current_leaf_count; i++) {
      memcpy(root_hashes[i], current_hashes[i], HASH_SIZE);
    }
    
    /* Generate current root hash */
    build_merkle_tree(root_hashes, current_leaf_count, debug);
    
    if (memcmp(root_hashes[0], proof->root_hash, HASH_SIZE) == 0) {
      printf("VERIFICATION PASSED: Data integrity confirmed\n");
      
      if (debug) {
        printf("[DEBUG] Root hash matches: ");
        for (int i = 0; i < HASH_SIZE; i++) {
          printf("%02x", root_hashes[0][i]);
        }
        printf("\n");
      }
      
      free_hash_storage(root_hashes);
      free_hash_storage(current_hashes);
      return 0;
    } else {
      printf("VERIFICATION FAILED: Root hash mismatch (unexpected)\n");
      if (debug) {
        printf("[DEBUG] Expected root: ");
        for (int i = 0; i < HASH_SIZE; i++) {
          printf("%02x", proof->root_hash[i]);
        }
        printf("\n");
        printf("[DEBUG] Calculated root: ");
        for (int i = 0; i < HASH_SIZE; i++) {
          printf("%02x", root_hashes[0][i]);
        }
        printf("\n");
      }
      differences_found = 1;
    }
    
    free_hash_storage(root_hashes);
  }
  
  free_hash_storage(current_hashes);
  return differences_found ? -1 : 0;
}

/*
 * Main processing function that computes the Merkle tree for input data.
 * Handles memory allocation, tree computation, and optional proof generation.
 *
 * Parameters:
 *   input_data     - pointer to the input data buffer
 *   input_len      - length of input data in bytes
 *   debug          - enable debug output and timing information
 *   generate_proof - if true, saves proof to JSON file
 *
 * Returns:
 *   0 on success, 1 on memory allocation failure
 */
int process_input(unsigned char *input_data, size_t input_len, int debug, int generate_proof) {
  if (debug) {
    printf("[DEBUG] === Starting Merkle Tree Computation ===\n");
    printf("[DEBUG] Input data size: %zu bytes\n", input_len);
  }

  /* Allocate hash storage dynamically based on input size */
  unsigned char **hashes = allocate_hash_storage(input_len, debug);
  if (!hashes) {
    fprintf(stderr, "Failed to allocate hash storage\n");
    return 1;
  }

  if (debug) {
    start_timer();
  }

  size_t leaf_count = chunk_and_hash(input_data, input_len, hashes, debug);
  
  /* Save leaf hashes for proof generation */
  unsigned char **proof_leaf_hashes = NULL;
  if (generate_proof) {
    proof_leaf_hashes = allocate_hash_storage(input_len, debug);
    if (proof_leaf_hashes) {
      for (size_t i = 0; i < leaf_count; i++) {
        memcpy(proof_leaf_hashes[i], hashes[i], HASH_SIZE);
      }
    }
  }
  
  build_merkle_tree(hashes, leaf_count, debug);

  if (debug) {
    double total_time = end_timer();
    printf("[DEBUG] Total computation time: %.6f seconds\n", total_time);
    printf("[DEBUG] Overall throughput: %.2f MB/s\n", 
           (input_len / (1024.0 * 1024.0)) / total_time);
    printf("[DEBUG] === Merkle Tree Computation Complete ===\n");
  }

  /* Print the resulting hash as a hex string */
  for (size_t i = 0; i < HASH_SIZE; i++) {
    printf("%02x", hashes[0][i]);
  }
  printf("\n");
  
  /* Generate proof if requested */
  if (generate_proof && proof_leaf_hashes) {
    struct merkle_proof proof;
    proof.leaf_hashes = proof_leaf_hashes;
    proof.leaf_count = leaf_count;
    proof.original_size = input_len;
    memcpy(proof.root_hash, hashes[0], HASH_SIZE);
    
    if (save_proof(&proof, debug) == 0) {
      if (debug) {
        printf("[DEBUG] Proof generation completed successfully\n");
      }
    }
    
    free_hash_storage(proof_leaf_hashes);
  }

  free_hash_storage(hashes);
  return 0;
}

int main(int argc, char *argv[]) {
  struct arguments arguments = {0};

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  /* Handle verification mode */
  if (arguments.verify_proof) {
    struct merkle_proof *proof = load_proof(arguments.verify_proof, arguments.debug);
    if (!proof) {
      fprintf(stderr, "Failed to load proof file\n");
      return 1;
    }
    
    unsigned char *input_data = NULL;
    size_t input_len = 0;
    int error = 0;
    
    /* Read data to verify */
    if (arguments.filename) {
      if (arguments.debug) {
        printf("[DEBUG] Reading verification data from file: %s\n", arguments.filename);
      }
      FILE *fp = fopen(arguments.filename, "rb");
      if (!fp) {
        perror("Error opening file");
        free_proof(proof);
        return 1;
      }
      error = read_input(fp, &input_data, &input_len, arguments.debug);
      fclose(fp);
    } else if (arguments.data) {
      if (arguments.debug) {
        printf("[DEBUG] Verifying string argument: \"%s\"\n", arguments.data);
      }
      input_len = strlen(arguments.data);
      input_data = malloc(input_len);
      if (!input_data) {
        fprintf(stderr, "Memory allocation failed\n");
        free_proof(proof);
        return 1;
      }
      memcpy(input_data, arguments.data, input_len);
    } else {
      /* Read from stdin */
      if (arguments.debug) {
        printf("[DEBUG] Reading verification data from stdin...\n");
      }
      error = read_input(stdin, &input_data, &input_len, arguments.debug);
    }
    
    if (error) {
      fprintf(stderr, "Failed to read verification data\n");
      free_proof(proof);
      return 1;
    }
    
    int result = verify_data_with_proof(input_data, input_len, proof, arguments.debug);
    
    free(input_data);
    free_proof(proof);
    return (result == 0) ? 0 : 1;
  }

  /* Normal processing mode */
  unsigned char *input_data = NULL;
  size_t input_len = 0;
  int error = 0;

  if (arguments.filename) {
    if (arguments.debug) {
      printf("[DEBUG] Reading from file: %s\n", arguments.filename);
    }
    FILE *fp = fopen(arguments.filename, "rb");
    if (!fp) {
      perror("Error opening file");
      return 1;
    }
    error = read_input(fp, &input_data, &input_len, arguments.debug);
    fclose(fp);
    if (error) {
      fprintf(stderr, "Failed to read file data\n");
      return 1;
    }
  } else if (arguments.data) {
    if (arguments.debug) {
      printf("[DEBUG] Processing string argument: \"%s\"\n", arguments.data);
    }
    input_len = strlen(arguments.data);
    input_data = malloc(input_len);
    if(!input_data) {
      fprintf(stderr, "Memory allocation failed\n");
      return 1;
    }
    memcpy(input_data, arguments.data, input_len);
  } else {
    /* Read from stdin */
    if (arguments.debug) {
      printf("[DEBUG] Reading from stdin...\n");
    }
    error = read_input(stdin, &input_data, &input_len, arguments.debug);
    if (error) {
      fprintf(stderr, "Failed to read stdin\n");
      return 1;
    }
  }

  int result = process_input(input_data, input_len, arguments.debug, arguments.generate_proof);
  free(input_data);
  return result;
}
