#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crypto_auth.h"
#include "crypto_aead.h"

#include "loramac.h"
#include "aes.h"

struct loramac_phys_payload *loramac_init(void)
{
	static struct loramac_phys_payload payload = {0};
	payload.mac_payload.frm_payload = NULL;
	payload.mac_payload.f_hdr.f_opts = NULL;
	
	return &payload;
}

int32_t loramac_fill_fhdr(struct loramac_phys_payload *payload, uint32_t dev_addr, uint8_t f_ctrl, uint16_t f_cnt, uint8_t *f_opts)
{
	payload->mac_payload.f_hdr.dev_addr = dev_addr;
	payload->mac_payload.f_hdr.f_ctrl = f_ctrl;
	payload->mac_payload.f_hdr.f_cnt = f_cnt;
	payload->mac_payload.f_hdr.f_opts = f_opts;

	return 0;
}

int32_t loramac_fill_mac_payload(struct loramac_phys_payload *payload, uint8_t f_port, uint8_t *frm_payload)
{
	payload->mac_payload.f_port = f_port;
	payload->mac_payload.frm_payload = frm_payload;

	return 0;
}

int32_t loramac_fill_phys_payload(struct loramac_phys_payload *payload, uint8_t m_hdr, uint8_t *mic)
{
	payload->m_hdr = m_hdr;
	if (mic){
		memcpy(payload->mic, mic, 16);
	}
	return 0;
}

static int32_t loramac_aes_byte_array_xor(uint8_t *byte_a, uint8_t b[16][16], uint8_t *out, uint32_t frm_payload_size)
{
	int i = 0;
	uint8_t total_block = (uint8_t)(frm_payload_size / 16) + (frm_payload_size % 16 ? 1 : 0);
	for (uint8_t block = 0; block < total_block; block++) {
		uint8_t *byte_b = b[block];
		for (int j = 15; j >= 0; j--) {
			out[i] = byte_a[i] ^ byte_b[j];
			i++;
			if (i >= frm_payload_size) {
				break;
			}
		}
	}
	return 0;
}

// TODO: support FOpts in calculation, currently it's skipped as FCTRL will always be 0x00
int32_t loramac_calculate_mic(struct loramac_phys_payload *payload, uint8_t frm_payload_size, uint8_t *key, uint8_t algo_option, uint32_t *mic)
{
	unsigned long long inlen = 9 + frm_payload_size + 16;
	uint8_t in[inlen]; // 9 bytes = MHDR + DEV_ADDR + FCTRL + FCNT + FPORT

	uint8_t out[16] = {0};
	uint8_t *B_dev_addr;
	uint8_t *B_f_cnt;

	memset(in, 0, inlen);

	uint8_t B[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	B[0] = 0x49;

	B_dev_addr = (uint8_t *)&payload->mac_payload.f_hdr.dev_addr;
	memcpy(&B[6], B_dev_addr, 4);
	B_f_cnt = (uint8_t *)&payload->mac_payload.f_hdr.f_cnt;
	memcpy(&B[10], B_f_cnt, 2);

	B[15] = frm_payload_size + 9; // FRM_PAYLOAD + MHDR + FHDR + FPORT
	
	memcpy(in, B, 16);
	in[16] = payload->m_hdr;
	memcpy(&in[17], (uint8_t *)&payload->mac_payload.f_hdr, 7);
	in[17 + 7] = payload->mac_payload.f_port;
	// Little endian payload
	for (uint16_t i = 17 + 7 + 1, j = frm_payload_size - 1; i < frm_payload_size + 17 + 7 + 1; i++, j--) {
		in[i] = payload->mac_payload.frm_payload[j]; // FRM_PAYLOAD starts from byte offset 9
	}
	// ASCON MAC
	if (algo_option) {
		int rc = crypto_auth(out, in, inlen, key);
		if (rc != 0) {
			return -1;
		}
	} else {
		return -2;
	}
	*mic = out[0];
	*mic |= out[1] << 8;
	*mic |= out[2] << (8 * 2);
	*mic |= out[3] << (8 * 3);
	return 0;
}

// TODO: support frm_payload_size greater than 16 bytes
// TODO: support other MType other than Unconfirmed up/down
int32_t loramac_frm_payload_encryption(struct loramac_phys_payload *payload, uint8_t frm_payload_size, uint8_t *key)
{
	uint8_t *Ai_dev_addr;
	uint8_t *Ai_f_cnt;

	uint8_t Ai[16][16] = {0};
	uint8_t S[16][16] = {0};

	Ai_dev_addr = (uint8_t *)&payload->mac_payload.f_hdr.dev_addr; // transform to little endian
	Ai_f_cnt = (uint8_t *)&payload->mac_payload.f_hdr.f_cnt;

	for (uint8_t i = 0; i < (uint8_t)(frm_payload_size / 16) + (frm_payload_size % 16 ? 1 : 0); i++) {
		Ai[i][0] = 0x01;
		Ai[i][5] = payload->m_hdr & 0x20 ? DOWNLINK : UPLINK;

		memcpy(&Ai[i][6], Ai_dev_addr, 4);
		memcpy(&Ai[i][10], Ai_f_cnt, 2);

		aes_context ctx = {0};
		aes_set_key(key, 16, &ctx);
		Ai[i][15] = i + 1;
		aes_encrypt(Ai[i], S[i], &ctx);
	}

	loramac_aes_byte_array_xor(payload->mac_payload.frm_payload, S, payload->mac_payload.frm_payload, frm_payload_size);

	return 0;
}

// TODO: support FOpts unknown length, skip it for now
int32_t loramac_serialize_data(struct loramac_phys_payload *payload, uint8_t *out_data, uint8_t frm_payload_size)
{
	memcpy(out_data, (uint8_t *)payload, 8); // MHDR -> FCNT
	out_data[8] = payload->mac_payload.f_port; // FPORT
	// Little endian payload
	for (uint16_t i = 9, j = frm_payload_size - 1; i < frm_payload_size + 9; i++, j--) {
		out_data[i] = payload->mac_payload.frm_payload[j]; // FRM_PAYLOAD starts from byte offset 9
	}
	memcpy(&out_data[9 + frm_payload_size], (uint8_t *)&payload->mic, 4); // MIC
	
	return 0;
}

int32_t loramac_enc_aead(struct loramac_phys_payload *payload, uint8_t *out, uint8_t *out_size, uint8_t frm_payload_size, uint8_t *key)
{
	uint8_t cipher[frm_payload_size + 16]; // ciphertext + tags
	uint8_t plaintext[frm_payload_size];
	memset(cipher, 0, frm_payload_size + 16);
	memset(plaintext, 0, frm_payload_size);
	
	uint64_t cipher_length_out = 0;
	uint8_t nonce[16] = {0};
	uint8_t ad[9] = {0}; // MHDR 1 + DevAddr 4 + FCtrl 1 + FCnt 2 + FPort 1
	uint8_t i;

	for (i = 0; i < frm_payload_size; i++){
		plaintext[i] = payload->mac_payload.frm_payload[frm_payload_size - 1 - i];
	}
	ad[0] = payload->m_hdr;
	
	ad[1] = payload->mac_payload.f_hdr.dev_addr & 0xFF;
	ad[2] = (payload->mac_payload.f_hdr.dev_addr >> 8) & 0xFF;
	ad[3] = (payload->mac_payload.f_hdr.dev_addr >> 16) & 0xFF;
	ad[4] = (payload->mac_payload.f_hdr.dev_addr >> 24) & 0xFF;
	ad[5] = payload->mac_payload.f_hdr.f_ctrl;
	
	ad[6] = payload->mac_payload.f_hdr.f_cnt & 0xFF;
	ad[7] = payload->mac_payload.f_hdr.f_cnt >> 8;
	
	ad[8] = payload->mac_payload.f_port;
	
	memcpy(nonce, ad, 5);
	nonce[5] = payload->mac_payload.f_hdr.f_cnt & 0xFF;
	nonce[6] = payload->mac_payload.f_hdr.f_cnt >> 8;
	
	int32_t ret = crypto_aead_encrypt(cipher, &cipher_length_out, plaintext, frm_payload_size, ad, sizeof(ad), NULL, nonce, key);

	// Sanity check
	if (((uint8_t)cipher_length_out) != (frm_payload_size + 16))
	{
		return -1;
	}

	if (ret) {
		return ret;
	}
	
	memcpy(out, ad, 9);
	memcpy(&out[9], cipher, (uint8_t)cipher_length_out);

	*out_size = (uint8_t)cipher_length_out + 9;

	return ret;
}

int32_t loramac_dec_aead(struct loramac_phys_payload *out, uint8_t *out_frm_payload, uint8_t *out_frm_payload_size, uint8_t *loramac_in, uint8_t loramac_in_size, uint8_t *key)
{
	uint8_t cipher[loramac_in_size - 9]; // Ciphertext + tag = in - (MHDR 1 + DevAddr 4 + FCtrl 1 + FCnt 2 + FPort 1)
	uint8_t plaintext[loramac_in_size - 9 - 16]; // plaintext
	memset(cipher, 0, loramac_in_size - 9);
	memset(plaintext, 0, loramac_in_size - 9 - 16);

	uint8_t nonce[16] = {0};
	uint8_t ad[9] = {0}; // MHDR 1 + DevAddr 4 + FCtrl 1 + FCnt 2 + FPort 1

	uint64_t plaintext_length_out = 0;

	memcpy(ad, loramac_in, 9);
	memcpy(cipher, &loramac_in[9], loramac_in_size - 9);
	memcpy(nonce, ad, 5);
	nonce[5] = ad[6];
	nonce[6] = ad[7];
	
	int32_t ret = crypto_aead_decrypt(plaintext, &plaintext_length_out, NULL, cipher, loramac_in_size - 9, ad, sizeof(ad), nonce, key);
	
	// Sanity check
	if (((uint8_t)plaintext_length_out) != (loramac_in_size - 9 - 16))
	{
		return -1;
	}

	if (ret) {
		return ret;
	}

	out->m_hdr = ad[0];
	out->mac_payload.f_hdr.dev_addr = (ad[4] << 24) | (ad[3] << 16) | (ad[2] << 8) | ad[1];
	out->mac_payload.f_hdr.f_ctrl = ad[5];
	out->mac_payload.f_hdr.f_cnt = (ad[7] << 8) | ad[6];
	out->mac_payload.f_port = ad[8];

	for(uint8_t i = 0; i < (uint8_t)plaintext_length_out; i++){
		out_frm_payload[i] = plaintext[(uint8_t)plaintext_length_out - 1 - i];
	}
	
	*out_frm_payload_size = (uint8_t)plaintext_length_out;

	return 0;
}

int32_t loramac_pack_join_request(struct loramac_phys_payload_join_request **jr_frame, uint8_t *app_eui, uint8_t *dev_eui, uint8_t *dev_nonce, uint8_t *appkey)
{
	static struct loramac_phys_payload_join_request frame = {0};
	uint8_t out[16] = {0};
	uint8_t i;

	frame.m_hdr = 0;

	for (i = 0; i < 8; i++){
		frame.app_eui[i] = app_eui[7 - i];
	}
	for (i = 0; i < 8; i++){
		frame.dev_eui[i] = dev_eui[7 - i];
	}
	for (i = 0; i < 2; i++){
		frame.dev_nonce[i] = dev_nonce[1 - i];
	}

	int rc = crypto_auth(out, &frame.m_hdr, sizeof(struct loramac_phys_payload_join_request) - sizeof(frame.mic), appkey);
	if (rc != 0) {
		return -2;
	}
	for (i = 0; i < sizeof(frame.mic); i++){
		frame.mic[i] = out[sizeof(frame.mic) - 1 - i];
	}

	*jr_frame = &frame;

	return 0;
}

int32_t loramac_update_join_request_nonce(struct loramac_phys_payload_join_request *jr_frame, uint8_t *new_dev_nonce)
{
	jr_frame->dev_nonce[0] = new_dev_nonce[1];
	jr_frame->dev_nonce[1] = new_dev_nonce[0];
	return 0;
}

int32_t loramac_pack_join_accept(struct loramac_phys_payload_join_accept **ja_frame, uint8_t *app_nonce, uint8_t *net_id, uint8_t *dev_addr, uint8_t *dl_settings, uint8_t *rx_delay, uint8_t *appkey)
{
	static struct loramac_phys_payload_join_accept frame = {0};
	uint64_t cipher_length_out = 0;
	uint8_t cipher[sizeof(struct loramac_phys_payload_join_accept)];
	memset(cipher, 0, sizeof(struct loramac_phys_payload_join_accept));
	uint8_t nonce[16] = {0};
	uint8_t ad[9] = {0}; // MHDR 1 + DevAddr 4 + FCtrl 1 + FCnt 2 + FPort 1
	uint8_t i, j;
	j = 0;
	frame.m_hdr = LORAMAC_PHYS_PAYLOAD_JOIN_ACCEPT;
	nonce[j++] = LORAMAC_PHYS_PAYLOAD_JOIN_ACCEPT;
	for (i = 0; i < 3; i++){
		frame.app_nonce[i] = app_nonce[2 - i];
		nonce[j++] = app_nonce[2 - i];
	}
	for (i = 0; i < 4; i++){
		frame.dev_addr[i] = dev_addr[3 - i];
	}
	for (i = 0; i < 3; i++){
		frame.net_id[i] = net_id[2 - i];
	}
	frame.dl_settings = dl_settings[0];
	frame.rx_delay = rx_delay[0];
	// Don't count MHDR + MIC
	uint64_t frame_len = sizeof(struct loramac_phys_payload_join_accept) - 1 - 16;
	// cipher[1] cause cipher[0] is ad (MHDR)
	int rc = crypto_aead_encrypt(&cipher[1], &cipher_length_out, frame.app_nonce, frame_len, &frame.m_hdr, 1, NULL, nonce, appkey);
	if (rc != 0) {
		return -2;
	}
	// Assign ciphertext back to struct loramac_phys_payload_join_accept
	uint8_t *frame_ptr = &frame.app_nonce[0];

	frame.m_hdr = LORAMAC_PHYS_PAYLOAD_JOIN_ACCEPT;
	for (i = 0; i < 12; i++) {
		frame_ptr[i] = cipher[i + 1];
	}
	for (i = 0; i < sizeof(frame.mic); i++){
		frame.mic[i] = cipher[i + 13];
	}
	*ja_frame = &frame;

	return 0;
}
