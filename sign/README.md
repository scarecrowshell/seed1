gcc -Wall -Wextra -O2 \
  seed.c \
  canonical/*.c \
  keymgmt/*.c \
  sign/mod.c \
  -lcrypto -lm \
  -o seed
