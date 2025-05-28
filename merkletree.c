/*
 * merkletree.c
 * A simple implementation of Merkle Trees in C with dynamic memory allocation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <unistd.h>
#include <openssl/evp.h>

#define DEFAULT_BUFFER_SIZE (1024 * 1024) /* 1 MB */
#define HASH_SIZE 32                      /* SHA3-256 produces 32-byte hashes */
#define BLOCK_SIZE (16 * 1024)            /* 16 KB for each node, 16KB hits the sweet spot between
                                             I/O troughtput and number of reads/writes  */

struct arguments {
  char *filename; /* --file FILE */
  char *data;     /* positional argument (string) */
};

/* argp parser options */
static struct argp_option options[] = {
  {"file", 'f', "FILE", 0, "Read input from file.", 0},
  {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;

  switch (key) {
    case 'f':
      arguments->filename = arg;
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
  "Generate Merkle Tree of the input data.", /* doc */
  NULL,
  NULL,
  NULL
};

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
 *
 * Returns:
 *    The number of chunks (leaf nodes) hashed.
 */
size_t chunk_and_hash(const unsigned char *buffer, size_t total_size, unsigned char **out_hashes) {
  size_t num_chunks = (total_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

  for (size_t i = 0; i < num_chunks; i++) {
    size_t offset = i * BLOCK_SIZE;
    size_t chunk_len = (offset + BLOCK_SIZE <= total_size) ? BLOCK_SIZE : (total_size - offset);
    keccak_256(buffer + offset, chunk_len, out_hashes[i]);
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
 */
void build_merkle_tree(unsigned char **hashes, size_t count) {
  while (count > 1) {
    size_t i, j = 0;
    for (i = 0; i < count; i += 2) {
      if (i + 1 < count) {
        hash_pair(hashes[i], hashes[i + 1], hashes[j]);
      } else {
        /* Duplicating the last node if the 
         * number of nodes are odd */
        hash_pair(hashes[i], hashes[i], hashes[j]);
      }
      j++;
    }
    count = j;
  }
}

/*
 * Allocate memory for hash storage based on input size
 *
 * Parameters:
 *    input_size - size of input data in bytes
 *
 * Returns:
 *    Pointer to allocated hash array, or NULL on failure
 */
unsigned char** allocate_hash_storage(size_t input_size) {
  size_t num_blocks = (input_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
  
  if (num_blocks == 0) {
    num_blocks = 1; // Handle empty input case
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
 *
 * Returns:
 *    0 on success, -1 on error
 */
int read_input(FILE *fp, unsigned char **buf, size_t *len) {
  size_t capacity = DEFAULT_BUFFER_SIZE;
  *buf = malloc(capacity);
  if (!*buf) return -1;

  size_t total = 0;
  while (1) {
    if (total == capacity) {
      capacity *= 2;
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
  *len = total;
  return 0;
}

int main(int argc, char *argv[]) {
  struct arguments arguments = {0};

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  unsigned char *input_data = NULL;
  size_t input_len = 0;
  int error = 0;

  if (arguments.filename) {
    FILE *fp = fopen(arguments.filename, "rb");
    if (!fp) {
      perror("Error opening file");
      return 1;
    }
    error = read_input(fp, &input_data, &input_len);
    fclose(fp);
    if (error) {
      fprintf(stderr, "Failed to read file data\n");
      return 1;
    }
  } else if (arguments.data) {
    input_len = strlen(arguments.data);
    input_data = malloc(input_len);
    if(!input_data) {
      fprintf(stderr, "Memory allocation failed\n");
      return 1;
    }
    memcpy(input_data, arguments.data, input_len);
  } else {
    /* Read from stdin */
    error = read_input(stdin, &input_data, &input_len);
    if (error) {
      fprintf(stderr, "Failed to read stdin\n");
      return 1;
    }
  }

  /* Allocate hash storage dynamically based on input size */
  unsigned char **hashes = allocate_hash_storage(input_len);
  if (!hashes) {
    fprintf(stderr, "Failed to allocate hash storage\n");
    free(input_data);
    return 1;
  }

  size_t leaf_count = chunk_and_hash(input_data, input_len, hashes);
  build_merkle_tree(hashes, leaf_count);

  printf("Merkle Root Hash: ");

  /* Print the resulting hash as a hex string */
  for (size_t i = 0; i < HASH_SIZE; i++) {
    printf("%02x", hashes[0][i]);
  }
  printf("\n");
  
  free_hash_storage(hashes);
  free(input_data);
  return 0;
}
