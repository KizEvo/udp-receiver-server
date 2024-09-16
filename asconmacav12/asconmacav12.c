#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crypto_auth.h"
#include "base64.h"
#include "secrets.h"

#define BASE64_INPUT_DATA argv[1]
#define BASE64_INPUT_SIZE argv[2][0]

static unsigned char key[CRYPTO_KEYBYTES] = {KEY};

static unsigned char tag[CRYPTO_BYTES];

int main(int argc, char *argv[])
{
    if (argc != 3) {
        return -1;
    }
    size_t data_out_size = 0;
    unsigned char *decoded = base64_decode(BASE64_INPUT_DATA, BASE64_INPUT_SIZE, &data_out_size);

    crypto_auth(tag, decoded, (unsigned long long)data_out_size, key);

    for (uint32_t i = 0; i < data_out_size; i++) {
        printf("%.2x", tag[i]);
    }

    base64_cleanup();
    return 0;
}