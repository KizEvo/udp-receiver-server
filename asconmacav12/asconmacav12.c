#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "crypto_auth.h"
#include "base64.h"
#include "loramac.h"
#include "aes.h"

#include <time.h>

#define BASE64_INPUT_DATA   argv[1]
#define APPSKEY_INPUT_DATA  argv[2]
#define NWSKEY_INPUT_DATA   argv[3]
#define DEV_ADDR_INPUT_DATA argv[4]
#define DOWN_CNT_INPUT_DATA argv[5]
#define FPORT_INPUT_DATA    argv[6]

#define APPNONCE_INPUT_DATA argv[1]
#define DLSETTIN_INPUT_DATA argv[3]
#define RXDELAY_INPUT_DATA  argv[5]
#define NETID_INPUT_DATA    argv[6]
#define DEVNONCE_INPUT_DATA argv[7]
/* x is pointer to unsigned char */
#define LE_BYTES_TO_UINT32(x) ((*(x + 3)) << 24) | ((*(x + 2)) << 16) | ((*(x + 1)) << 8) | ((*(x)))
#define LE_BYTES_TO_UINT16(x) ((*(x + 1)) << 8) | ((*(x)))
#define LE_UINT32(x) (((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000))

#define DEVICES_ADDRBYTES 4
#define APPNONCE_BYTES    3
#define DLSETTIN_BYTES    1
#define RXDELAY_BYTES     1
#define NETID_BYTES       3
#define DEVNONCE_BYTES    2

#ifndef CRYPTO_BYTES
#define CRYPTO_BYTES 16
#endif

static unsigned char nwskey1[CRYPTO_KEYBYTES] = { 0 };
static unsigned char appskey1[CRYPTO_KEYBYTES] = { 0 };

static unsigned char appnonce[APPNONCE_BYTES] = {0};
static unsigned char dlsettings[DLSETTIN_BYTES] = {0};
static unsigned char rxdelay[RXDELAY_BYTES] = {0};
static unsigned char netid[NETID_BYTES] = {0};
static unsigned char devnonce[DEVNONCE_BYTES] = {0};

static unsigned char tag[CRYPTO_BYTES] = { 0 };

static unsigned char devices[DEVICES_ADDRBYTES] = { 0 };

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
    size_t hexLen = strlen(hexString);

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

    // Convert hex string to byte array
    if (hex_string_to_byte(DEV_ADDR_INPUT_DATA, devices, 4) != 0) {
        printf("\nCan not convert to byte array for device address");
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
    struct loramac_phys_payload *loramac_payload = loramac_init();

    uint32_t dev_addr = (devices[0] << 24) | (devices[1] << 16) | (devices[2] << 8) | devices[3];
    uint32_t loramac_f_cnt = (uint32_t)atoi(DOWN_CNT_INPUT_DATA);
    uint8_t f_port = (uint8_t)atoi(FPORT_INPUT_DATA);
    uint8_t lora_package[data_out_size + 25]; // FRM_PAYLOAD + 25 modified LoRaWAN protocol AEAD excepts FOpts
    uint8_t lora_package_size = 0;

    loramac_fill_fhdr(loramac_payload, dev_addr, 0, loramac_f_cnt, 0);
	loramac_fill_mac_payload(loramac_payload, f_port, decoded);
	loramac_fill_phys_payload(loramac_payload, LORAMAC_PHYS_PAYLOAD_MHDR_UNCONFIRM_DATA_DOWN, 0);

	// fully constructed LoRaWAN package: header + frm_payload + MIC (tag)
	int res = loramac_enc_aead(loramac_payload, lora_package, &lora_package_size, data_out_size, appskey1);

    if (res) {
        printf("\nEncryption failed");
        return res;
    }
    printf("\n");
    for (uint8_t i = 0; i < lora_package_size; i++) {
        printf("%.2x", lora_package[i]);
    }
    printf("\n");
    return 0;
}

static int32_t lora_asconmac_decrypt(char *argv[])
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
    size_t data_in_size = strlen(BASE64_INPUT_DATA);
    if (!data_in_size) {
        /* cannot convert to a number */
        printf("\nCan not get size of data input");
        return -2;
    }
    /* Base64 decoded package - [MHDR + FHDR + FPORT + FRMPayload + MIC] */
    unsigned char *decoded = base64_decode(BASE64_INPUT_DATA, data_in_size, &data_out_size);
    /* Use the LoRaMAC API to calculate the MIC and compare with decoded MIC */
    struct loramac_phys_payload *payload = loramac_init();
    uint8_t frm_payload_size = data_out_size - (1 + 4 + 1 + 2 + 1 + 16); /* [MHDR + FHDR[DevAddr + ..] + FPORT + MIC] */
    uint8_t out_frm_payload[255] = {0};
    uint8_t out_frm_payload_size = 0;

    int res = loramac_dec_aead(payload, out_frm_payload, &out_frm_payload_size, decoded, data_out_size, appskey1);
    end = clock();
    if (res) {
        printf("\nCan not decrypt message size %zu with input size %zu: 0x", data_out_size, data_in_size);
        for (uint8_t i = 0; i < data_out_size; i++) {
            printf("%.2x", decoded[i]);
        }
        printf("\n");
        return -3;
    }
    if (out_frm_payload_size != frm_payload_size) {
        printf("\nSize expectation does not match: %u %u", out_frm_payload_size, frm_payload_size);
        return -4;
    }
    printf("\n");
    double elapsed_time_in_us = (double)(end - start) * 1000000.0 / CLOCKS_PER_SEC;
    for (uint8_t i = 0; i < out_frm_payload_size; i++) {
        printf("%.2x", out_frm_payload[i]);
    }
    printf("\n");
    printf("%.8u\n", (uint64_t)elapsed_time_in_us);
    printf("%.8x\n", payload->mac_payload.f_hdr.dev_addr);
    printf("%.4x\n", payload->mac_payload.f_hdr.f_cnt);
    printf("%.2x\n", payload->mac_payload.f_port);
    printf("%.2x\n", payload->m_hdr);
    base64_cleanup();
    return 0;
}

static int lora_join_request_check(char *argv[])
{
    // Convert hex string to byte array
    if (hex_string_to_byte(APPSKEY_INPUT_DATA, appskey1, 16) != 0) {
        printf("\nCan not convert to byte array for appskey");
        return -1;
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
    /* Init join-request struct */
    struct loramac_phys_payload_join_request *jr_frame_in = (struct loramac_phys_payload_join_request *)decoded;
    /* Turn Le to Be */
    reverse_bytes(jr_frame_in->app_eui, 8);
    reverse_bytes(jr_frame_in->dev_eui, 8);
    reverse_bytes(jr_frame_in->dev_nonce, 2);
    /* Pack the frame */
    struct loramac_phys_payload_join_request *jr_frame_out;
    loramac_pack_join_request(&jr_frame_out, jr_frame_in->app_eui, jr_frame_in->dev_eui, jr_frame_in->dev_nonce, appskey1);
    /* Check MIC */
    for (uint8_t i = 0; i < sizeof(jr_frame_out->mic); i++) {
        if (jr_frame_out->mic[i] != jr_frame_in->mic[i]) {
            printf("\nMIC does not match join-request");
            return -3;
        }
    }
    base64_cleanup();
    return 0;
}

static int lora_join_accept_process(char *argv[])
{
    // Process join-accept
    // Generate AppSKey and NwkSKey
    // Pack join-accept message
    // => 3 outputs to NodeJS

    // Convert hex string to byte array
    if (hex_string_to_byte(APPNONCE_INPUT_DATA, appnonce, APPNONCE_BYTES) != 0) {
        printf("\nCan not convert to byte array for appnonce");
        return -1; // Exit on error
    }

    // Device provisioned key (only known to device + network server)
    if (hex_string_to_byte(APPSKEY_INPUT_DATA, appskey1, CRYPTO_KEYBYTES) != 0) {
        printf("\nCan not convert to byte array for appkey");
        return -1; // Exit on error
    }

    // Convert hex string to byte array
    if (hex_string_to_byte(DLSETTIN_INPUT_DATA, dlsettings, DLSETTIN_BYTES) != 0) {
        printf("\nCan not convert to byte array for dlsettings");
        return -1; // Exit on error
    }

    // Convert hex string to byte array
    if (hex_string_to_byte(DEV_ADDR_INPUT_DATA, devices, DEVICES_ADDRBYTES) != 0) {
        printf("\nCan not convert to byte array for devaddr");
        return -1; // Exit on error
    }

    // Convert hex string to byte array
    if (hex_string_to_byte(RXDELAY_INPUT_DATA, rxdelay, RXDELAY_BYTES) != 0) {
        printf("\nCan not convert to byte array for rxdelay");
        return -1; // Exit on error
    }

    // Convert hex string to byte array
    if (hex_string_to_byte(NETID_INPUT_DATA, netid, NETID_BYTES) != 0) {
        printf("\nCan not convert to byte array for netid");
        return -1; // Exit on error
    }

    // Convert hex string to byte array
    if (hex_string_to_byte(DEVNONCE_INPUT_DATA, devnonce, DEVNONCE_BYTES) != 0) {
        printf("\nCan not convert to byte array for devnonce");
        return -1; // Exit on error
    }
    uint8_t out_nwkskey[CRYPTO_KEYBYTES] = {0};
    uint8_t out_appskey[CRYPTO_KEYBYTES] = {0};
    uint8_t out_ja_decrypted[CRYPTO_KEYBYTES] = {0};

    uint8_t in_nwkskey[CRYPTO_KEYBYTES] = {0};
    uint8_t in_appskey[CRYPTO_KEYBYTES] = {0};

    struct join_accept_xskey_input in = {0};
    uint8_t i;
    // nwkskey
    in.byte1 = 0x01;
    for (i = 0; i < APPNONCE_BYTES; i++) {
        in.app_nonce[i] = appnonce[APPNONCE_BYTES - 1 - i];
    }
    for (i = 0; i < NETID_BYTES; i++) {
        in.net_id[i] = netid[NETID_BYTES - 1 - i];
    }
    for (i = 0; i < DEVNONCE_BYTES; i++) {
        in.dev_nonce[i] = devnonce[DEVNONCE_BYTES - 1 - i];
    }
    crypto_auth(out_nwkskey, &in.byte1, sizeof(struct join_accept_xskey_input), appskey1);

    // appskey
    in.byte1 = 0x02;
    for (i = 0; i < APPNONCE_BYTES; i++) {
        in.app_nonce[i] = appnonce[APPNONCE_BYTES - 1 - i];
    }
    for (i = 0; i < NETID_BYTES; i++) {
        in.net_id[i] = netid[NETID_BYTES - 1 - i];
    }
    for (i = 0; i < DEVNONCE_BYTES; i++) {
        in.dev_nonce[i] = devnonce[DEVNONCE_BYTES - 1 - i];
    }
    crypto_auth(out_appskey, &in.byte1, sizeof(struct join_accept_xskey_input), appskey1);

    // prepare join-accept
    struct loramac_phys_payload_join_accept *ja_frame;
    int retval = loramac_pack_join_accept(&ja_frame, appnonce, netid, devices, dlsettings, rxdelay, appskey1);
    if (retval) {
        printf("\nCan not pack join_accept: %d", retval);
        return -1;
    }
    // Print to stdin
    printf("\n\n");
    for (i = 0; i < CRYPTO_KEYBYTES; i++) {
        printf("%.2x", out_nwkskey[i]);
    }
    printf("\n");
    for (i = 0; i < CRYPTO_KEYBYTES; i++) {
        printf("%.2x", out_appskey[i]);
    }
    printf("\n");
    uint8_t *ja_frame_ptr = &ja_frame->m_hdr;
    for (i = 0; i < sizeof(struct loramac_phys_payload_join_accept); i++) {
        printf("%.2x", ja_frame_ptr[i]);
    }

    printf("\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 3) {
        return lora_join_request_check(argv);
    } if (argc == 4) {
        return lora_asconmac_decrypt(argv);
    } else if (argc == 7) {
        return lora_asconmac_encrypt(argv);
    } else if (argc == 8) {
        return lora_join_accept_process(argv);
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
