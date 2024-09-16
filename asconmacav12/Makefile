all:
	@echo "Usage:"
	@echo "make asconmac"

asconmac:
	gcc -march=native -std=c99 -I secrets/ -I ref/ ref/*.c -I base64/ base64/*.c -I interface asconmacav12.c -o out
