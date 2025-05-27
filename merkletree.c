/*
 * merkletree.c
 * A simple implementation of Merkle Trees in C
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

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

int main() {
  const char *input = "brrrrr";
  unsigned char hash[32];          

  /* Compute the SHA3-256 hash of the input string */
  keccak_256((const unsigned char *)input, strlen(input), hash);

  /* Print the resulting hash as a hex string */
  for (int i = 0; i < 32; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");

  return 0;
}

