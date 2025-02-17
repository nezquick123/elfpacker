# elfpacker
A simple 64-bit ELF (Executable and Linkable Format) file packer

It "encrypts" the .text section using a key given as an argument with a xor operation. Packer will work only if there's enough space for the decrypting shellcode to be placed after the last executable section and before the start of the next memory page.

### Usage:
```
./elfpacker <path to elf> <key>
```
