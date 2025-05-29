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



struct arguments {
  char *filename; /* --file FILE */
  char *data;     /* positional argument (string) */
  int debug;      /* --debug flag */
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

    case ARGP_KEY_ARG:
      if (arguments->data != NULL) {
        /* positional argument */
        argp_usage(state);
      }
      arguments->data = arg;
      break;

    case ARGP_KEY_END:
      /* If no input source specified, check if stdin is a pipe */
      if (!arguments->filename && !arguments->data && isatty(fileno(stdin))) {
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
  "  merkletree \"hello world\"           # Hash string\n"
  "  merkletree -f myfile.txt            # Hash file\n"
  "  cat data.bin | merkletree           # Hash from stdin\n"
  "  merkletree -d \"test\"                # Debug mode", /* doc */
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



/* Process input and compute Merkle root */
int process_input(unsigned char *input_data, size_t input_len, int debug) {
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

  double total_start = 0;
  if (debug) {
    start_timer();
  }

  size_t leaf_count = chunk_and_hash(input_data, input_len, hashes, debug);
  build_merkle_tree(hashes, leaf_count, debug);

  if (debug) {
    double total_time = end_timer();
    printf("[DEBUG] Total computation time: %.6f seconds\n", total_time);
    printf("[DEBUG] Overall throughput: %.2f MB/s\n", 
           (input_len / (1024.0 * 1024.0)) / total_time);
    printf("[DEBUG] === Merkle Tree Computation Complete ===\n");
  }

  printf("Merkle Root Hash: ");

  /* Print the resulting hash as a hex string */
  for (size_t i = 0; i < HASH_SIZE; i++) {
    printf("%02x", hashes[0][i]);
  }
  printf("\n");

  free_hash_storage(hashes);
  return 0;
}

int main(int argc, char *argv[]) {
  struct arguments arguments = {0};

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

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

  int result = process_input(input_data, input_len, arguments.debug);
  free(input_data);
  return result;
}
