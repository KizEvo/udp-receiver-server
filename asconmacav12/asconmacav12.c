#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "crypto_auth.h"
#include "base64.h"
#include "loramac.h"

#include <time.h>

#define BASE64_INPUT_DATA  argv[1]
#define APPSKEY_INPUT_DATA argv[2]
#define NWSKEY_INPUT_DATA  argv[3]
/* x is pointer to unsigned char */
#define LE_BYTES_TO_UINT32(x) ((*(x + 3)) << 24) | ((*(x + 2)) << 16) | ((*(x + 1)) << 8) | ((*(x)))
#define LE_BYTES_TO_UINT16(x) ((*(x + 1)) << 8) | ((*(x)))
#define LE_UINT32(x) (((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000))

#define DEVICES_ADDRBYTES 4

static unsigned char nwskey1[CRYPTO_KEYBYTES] = { 0 };
static unsigned char appskey1[CRYPTO_KEYBYTES] = { 0 };

static unsigned char tag[CRYPTO_BYTES] = { 0 };

static uint32_t devices[DEVICES_ADDRBYTES] = { 0 };

void reverse_bytes(uint8_t *bytes, size_t size);

// Function to convert a hex character to its decimal value (0-15)
uint8_t hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    } else if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    return 0; // Invalid character (default to 0, but this should be handled as an error)
}

// Function to convert a hex string to a uint8_t array
int hex_string_to_byte(const char *hexString, uint8_t *byteArray, size_t arraySize) {
    // Check if the hex string is exactly 32 characters long (for 16 bytes)
    size_t hexLen = strlen(hexString);
    if (hexLen != 32) {
        printf("Hex string must be exactly 32 characters long, got %zu\n", hexLen);
        return -1;
    }

    // Check if the array size is 16
    if (arraySize != 16) {
        printf("Array size must be 16, got %zu\n", arraySize);
        return -1;
    }

    // Convert each pair of hex characters to a byte
    for (size_t i = 0; i < hexLen; i += 2) {
        uint8_t highNibble = hex_char_to_value(hexString[i]);     // First character (high 4 bits)
        uint8_t lowNibble = hex_char_to_value(hexString[i + 1]);   // Second character (low 4 bits)
        byteArray[i / 2] = (highNibble << 4) | lowNibble;      // Combine into one byte
    }

    return 0;
}

static int32_t lora_asconmac_encrypt(char *argv[])
{
    clock_t start, end;
    start = clock();
    // Convert hex string to byte array
    if (hex_string_to_byte(APPSKEY_INPUT_DATA, appskey1, 16) != 0) {
        printf("\nCan not convert to byte array for appskey");
        return -1; // Exit on error
    }

    // Convert hex string to byte array
    if (hex_string_to_byte(NWSKEY_INPUT_DATA, nwskey1, 16) != 0) {
        printf("\nCan not convert to byte array for nwskey");
        return -1; // Exit on error
    }

    size_t data_out_size = 0;
    size_t data_in_size = strlen((const char *)BASE64_INPUT_DATA);
    if (!data_in_size) {
        /* cannot convert to a number */
        printf("\nCan not get size of data input");
        return -2;
    }
    /* Base64 decoded package - [MHDR + FHDR + FPORT + FRMPayload + MIC] */
    unsigned char *decoded = base64_decode(BASE64_INPUT_DATA, data_in_size, &data_out_size);
    /* Use the LoRaMAC API to calculate the MIC and compare with decoded MIC */
    struct loramac_phys_payload *payload = loramac_init();
    uint8_t frm_payload_size = data_out_size - (1 + 4 + 1 + 2 + 1 + 4); /* [MHDR + FHDR[DevAddr + ..] + FPORT + MIC] */
    uint32_t dev_addr = LE_BYTES_TO_UINT32((&decoded[LRMAC_BYTE_OFFSET_DEVADDR]));
    uint16_t f_cnt = LE_BYTES_TO_UINT16((&decoded[LRMAC_BYTE_OFFSET_FCNT]));
    uint8_t f_ctrl = decoded[LRMAC_BYTE_OFFSET_FCTRL];

    loramac_fill_fhdr(payload, dev_addr, f_ctrl, f_cnt, NULL);

    uint8_t f_port = decoded[LRMAC_BYTE_OFFSET_FPORT];
    uint8_t *frm_payload = &decoded[LRMAC_BYTE_OFFSET_FRMPAYLOAD];
    reverse_bytes(frm_payload, frm_payload_size);
    loramac_fill_mac_payload(payload, f_port, frm_payload);

    uint8_t m_hdr = decoded[LRMAC_BYTE_OFFSET_MHDR];

    loramac_fill_phys_payload(payload, m_hdr, 0);

    if (f_ctrl & 0xF) {
        /* currently not support FOpts */
        printf("\nFOpts is asserted but we don't support it");
        return -3;
    }
    uint32_t mic = 0;
    uint32_t decoded_mic = 0;
    /* Compare MIC */
    loramac_calculate_mic(payload, frm_payload_size, nwskey1, 1, &mic);
    decoded_mic = LE_BYTES_TO_UINT32(&decoded[LRMAC_BYTE_OFFSET_FRMPAYLOAD + frm_payload_size]);
    if (mic != decoded_mic) {
        printf("\nMIC does not match");
        return -4;
    }
    /*
     * Decrypt LoRaWAN payload
     *
     * Yes I know, the function name is 'encryption' then
     * how can it decrypt ? The LoRaWAN payload encryption
     * and decryption is special because the algorithm does
     * not run with the payload as input but rather a block
     * called A[16] which is specified in the spec. This get
     * encrypted and produce S[16] and then it's XOR with the
     * LoRaWAN payload.
     *
     * So now we can just run the encryption function. Which
     * will produce the same S[16] and XOR with the encrypted
     * data will produce the decrypted payload.
     *
     * Check the spec if this is not clear to you.
     */
    loramac_frm_payload_encryption(payload, frm_payload_size, appskey1);
    end = clock();
    double elapsed_time_in_us = (double)(end - start) * 1000000.0 / CLOCKS_PER_SEC;
    for (uint8_t i = 0; i < frm_payload_size; i++) {
        printf("%.2x", frm_payload[i]);
    }
    printf("\n");
    printf("%.8u\n", (uint64_t)elapsed_time_in_us);
    printf("%x\n", dev_addr);
    printf("%.4x\n", f_cnt);
    printf("%.2x\n", f_port);
    printf("%.2x\n", m_hdr);
    base64_cleanup();
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 4) {
        return lora_asconmac_encrypt(argv);
    }
    /* invalid input parameter size */
    printf("\nInvalid input parameter size: %d", argc);
    return -1;
}

void reverse_bytes(uint8_t *bytes, size_t size)
{
    uint8_t limit = 0;
    if (size <= 1) {
        return;
    }
    for (uint8_t i = 0, j = size - 1; i < size / 2; i++, j--) {
        uint8_t tmp = bytes[j];
        bytes[j] = bytes[i];
        bytes[i] = tmp;
    }
}
