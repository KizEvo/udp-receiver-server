all:
	@echo "Usage:"
	@echo "make asconmac"
	@echo "help: The output is a 128 bit tags, display in hex format"
	@echo "      Usage './out <base64_encoded_string>'"

asconmac:
	gcc -march=native -std=c99 -I secrets/ -I ref/ ref/*.c -I base64/ base64/*.c -I interface asconmacav12.c -o out
