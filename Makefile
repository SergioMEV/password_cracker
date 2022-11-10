CC := clang
CFLAGS := -g -Wall -Werror -fsanitize=address

all: password-cracker

clean:
	rm -rf password-cracker password-cracker.dSYM

password-cracker: password-cracker.c
	$(CC) $(CFLAGS) -o password-cracker password-cracker.c -lcrypto -lpthread -lm

zip:
	@zip -q -r password-cracker.zip . -x .git/\* .vscode/\* inputs/\* .clang-format .gitignore password-cracker
	@echo "Done."

format:
	@echo "Reformatting source code."
	@clang-format -i --style=file $(wildcard *.c) $(wildcard *.h)
	@echo "Done."

.PHONY: all clean zip format
