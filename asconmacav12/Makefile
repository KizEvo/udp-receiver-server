all:
	@echo "Usage:"
	@echo "make asconmac"
	@echo "help: The output is consists of decrypted payload, device number, FCnt, FPort, MHDR."
	@echo "      Usage './out <base64_encoded_string>'"

asconmac:
	gcc -march=native -std=c99 -I ref/ ref/*.c -I base64/ base64/*.c -I loramac/ loramac/*.c -I aes/ aes/*.c -I interface asconmacav12.c -o out
