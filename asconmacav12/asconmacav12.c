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

static unsigned char nwskey1[CRYPTO_KEYBYTES] = {NWKSKEY1};

static unsigned char tag[CRYPTO_BYTES] = { 0 };

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
    /* Base64 decoded package - [MHDR + FHDR + FPORT + FRMPayload + MIC] */
    unsigned char *decoded = base64_decode(BASE64_INPUT_DATA, data_in_size, &data_out_size);
    /* Use the LoRaMAC API to calculate the MIC and compare with decoded MIC */
    struct loramac_phys_payload *payload = loramac_init();

    uint32_t dev_addr = LE_BYTES_TO_UINT32((&decoded[LRMAC_BYTE_OFFSET_DEVADDR]));
    uint16_t f_cnt = LE_BYTES_TO_UINT16((&decoded[LRMAC_BYTE_OFFSET_FCNT]));
    uint8_t f_ctrl = decoded[LRMAC_BYTE_OFFSET_FCTRL];

    loramac_fill_fhdr(payload, dev_addr, f_ctrl, f_cnt, NULL);

    uint8_t f_port = decoded[LRMAC_BYTE_OFFSET_FPORT];
    uint8_t *frm_payload = &decoded[LRMAC_BYTE_OFFSET_FRMPAYLOAD];

    loramac_fill_mac_payload(payload, f_port, frm_payload);

    uint8_t m_hdr = decoded[LRMAC_BYTE_OFFSET_MHDR];

    loramac_fill_phys_payload(payload, m_hdr, 0);

    if (f_ctrl & 0xF) {
        /* currently not support FOpts */
        return -3;
    }
    uint8_t frm_payload_size = data_out_size - (1 + 4 + 1 + 2 + 1 + 4); /* [MHDR + FHDR[DevAddr + ..] + FPORT + MIC] */
    uint32_t mic = 0;
    loramac_calculate_mic(payload, frm_payload_size, nwskey1, 1, &mic);

    printf("%x", mic);
    printf("\n");

    base64_cleanup();
    return 0;
}