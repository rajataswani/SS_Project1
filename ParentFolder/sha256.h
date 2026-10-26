#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

void sha256_hash_string(const char *input, char output_hex[65]);

#endif /* SHA256_H */
