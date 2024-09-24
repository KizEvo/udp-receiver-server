#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "crypto_auth.h"
#include "base64.h"
#include "secrets.h"
#include "loramac.h"

#define BASE64_INPUT_DATA argv[1]
/* x is pointer to unsigned char */
#define LE_BYTES_TO_UINT32(x) ((*(x + 3)) << 24) | ((*(x + 2)) << 16) | ((*(x + 1)) << 8) | ((*(x)))
#define LE_BYTES_TO_UINT16(x) ((*(x + 1)) << 8) | ((*(x)))
#define LE_UINT32(x) (((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000))
static unsigned char nwskey1[CRYPTO_KEYBYTES] = {NWKSKEY1};
static unsigned char appskey1[CRYPTO_KEYBYTES] = {APPSKEY1};

static unsigned char tag[CRYPTO_BYTES] = { 0 };

static uint32_t devices[] = {DEV_ADDR1};

void reverse_bytes(uint8_t *bytes, size_t size);

int main(int argc, char *argv[])
{
    if (argc != 2) {
        /* invalid input parameter size */
        return -1;
    }

    size_t data_out_size = 0;
    size_t data_in_size = strlen((const char *)BASE64_INPUT_DATA);
    if (!data_in_size) {
        /* cannot convert to a number */
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
        return -3;
    }
    uint32_t mic = 0;
    uint32_t decoded_mic = 0;
    /* We should loop for every keys here */
    uint8_t curr_dev = 0;
    for (; curr_dev < sizeof(devices) / sizeof(uint32_t); curr_dev++) {
        loramac_calculate_mic(payload, frm_payload_size, nwskey1, 1, &mic);
        decoded_mic = LE_BYTES_TO_UINT32(&decoded[LRMAC_BYTE_OFFSET_FRMPAYLOAD + frm_payload_size]);
        if (mic == decoded_mic) {
            curr_dev += 1;
            break;
        }
    }
    if (mic != decoded_mic) {
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
    for (uint8_t i = 0; i < frm_payload_size; i++) {
        printf("%.2x", frm_payload[i]);
    }
    printf("\n");
    printf("%.2u\n", curr_dev);
    printf("%x\n", dev_addr);
    printf("%.4x\n", f_cnt);
    printf("%.2x\n", f_port);
    printf("%.2x\n", m_hdr);
    base64_cleanup();
    return 0;
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
