gcc -ggdb3 \
    -I"mbedtls-2.16.1/include/" -L"mbedtls-2.16.1/library/" -o 0x0026 0x0026.c \
    -lmbedtls -lmbedx509 -lmbedcrypto
