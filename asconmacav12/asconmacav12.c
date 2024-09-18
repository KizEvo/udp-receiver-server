#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crypto_auth.h"
#include "base64.h"
#include "secrets.h"

#define BASE64_INPUT_DATA argv[1]

static unsigned char key[CRYPTO_KEYBYTES] = {KEY};

static unsigned char tag[CRYPTO_BYTES];

int main(int argc, char *argv[])
{
    if (argc != 2) {
        /* invalid input parameter size */
        return -1;
    }

    size_t data_out_size = 0;
    size_t data_in_size = sizeof(BASE64_INPUT_DATA);

    if (!data_in_size) {
        /* cannot convert to a number */
        return -2;
    }
    unsigned char *decoded = base64_decode(BASE64_INPUT_DATA, data_in_size, &data_out_size);

    crypto_auth(tag, decoded, (unsigned long long)data_out_size, key);

    for (uint32_t i = 0; i < CRYPTO_BYTES; i++) {
        printf("%.2x", tag[i]);
    }
    printf("\n");

    base64_cleanup();
    return 0;
}