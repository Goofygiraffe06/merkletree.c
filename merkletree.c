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

#define DEFAULT_BUFFER_SIZE (1024 * 1024) /* 1 MB */
#define HASH_SIZE 32                      /* SHA3-256 produces 32-byte hashes */

struct arguments {
  char *filename; /* --file FILE */
  char *data;     /*positional argument (string) */
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

  unsigned char hash[HASH_SIZE];
  /* Compute the SHA3-256 hash of the input string */
  keccak_256(input_data, input_len, hash);

  /* Print the resulting hash as a hex string */
  for (int i = 0; i < 32; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");
  
  free(input_data);
  return 0;
}

