package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
)

type fileHeader struct {
	E_ident     [16]byte
	E_type      uint16
	E_machine   uint16
	E_version   uint32
	E_entry     uint64
	E_phoff     uint64
	E_shoff     uint64
	E_flags     uint32
	E_ehsize    uint16
	E_phentsize uint16
	E_phnum     uint16
	E_shentsize uint16
	E_shnum     uint16
	E_shstrndx  uint16
} //64B

type sectionHeader struct {
	Sh_name      uint32
	Sh_type      uint32
	Sh_flags     uint64
	Sh_addr      uint64
	Sh_offset    uint64
	Sh_size      uint64
	Sh_link      uint32
	Sh_info      uint32
	Sh_addralign uint64
	Sh_entsize   uint64
} //64B

const PageSize int = 4096

func encrypt(section []byte, key string) []byte {
	encrypted := make([]byte, len(section))
	copy(encrypted, section)

	for i := 0; i < len(encrypted); i++ {
		encrypted[i] = encrypted[i] ^ key[i%len(key)]
	}

	return encrypted
}

func getShellcode(key string, textLen, loadAddr, pageStart, textStart, orgEntry int) []byte {
	var shellcode []byte
	var strShellcode string

	loadAddrStr := fmt.Sprintf("0x%x", loadAddr)
	pageStartStr := fmt.Sprintf("0x%x", pageStart)
	orgEntryStr := fmt.Sprintf("0x%x", orgEntry)
	textStartStr := fmt.Sprintf("0x%x", textStart)
	textSize := fmt.Sprintf("0x%x", (textLen/PageSize+1)*PageSize)
	textEndStr := fmt.Sprintf("0x%x", textStart+textLen)

	strShellcode = `[bits 64]
[org ` + loadAddrStr + `]
push rax
push rdi
push rsi
push rdx
push rcx
push r8
push r9
push r10
push r11
push rbx

mov rax, 0xa
mov rdi, ` + pageStartStr + `
mov rsi, ` + textSize + `
mov rdx, 7
syscall

mov rcx, ` + textEndStr + `
mov rdx, ` + textStartStr + `
mov r8, ` + strconv.Itoa(len(key)) + `; key length
mov r9, key
mov r10, 0
loop:
cmp rcx, rdx
je end
cmp r10, r8
jne loop2
mov r10, 0
loop2:
mov r11, r10
add r11, r9
mov bl, [r11]
mov al, [rdx]
xor al, bl
mov [rdx], al
inc rdx
inc r10
jmp loop


mov rax, 0xa
mov rdi, ` + pageStartStr + `
mov rsi, ` + textSize + `
mov rdx, 5
syscall

end:
pop rbx
pop r11
pop r10
pop r9
pop	r8
pop rcx
pop rdx
pop rsi
pop rdi
pop rax

jmp ` + orgEntryStr + `

key db "` + key + `", 0
`
	err := os.WriteFile("shellcode.nasm", []byte(strShellcode), 0644)
	if err != nil {
		fmt.Println(err)
	}
	err = exec.Command("nasm", "shellcode.nasm").Run()
	if err != nil {
		fmt.Println(err)
	}

	shellcode, err = os.ReadFile("shellcode")
	if err != nil {
		fmt.Println(err)
	}
	return shellcode
}

func toByteArray(i uint64) (arr [8]byte) {
	binary.LittleEndian.PutUint64(arr[:], i)
	return
}

func main() {
	var header fileHeader

	args := os.Args[1:]
	if len(args) < 2 {
		fmt.Println("Usage: ./elfpacker <path to elf> <key>")
		return
	}

	file, err := os.Open(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
		return
	}

	elfHeader := content[:64]
	buf := bytes.NewBuffer(elfHeader)
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		fmt.Println(err)
		return
	}

	sections := make([]sectionHeader, header.E_shnum)
	sectionNames := make([]string, header.E_shnum)
	startAddr := header.E_shoff
	sectionNum := 0
	for sectionNum < int(header.E_shnum) {
		buf = bytes.NewBuffer(content[startAddr : startAddr+64])
		err = binary.Read(buf, binary.LittleEndian, &sections[sectionNum])
		if err != nil {
			fmt.Println(err)
			return
		}
		startAddr += 64
		sectionNum++
	}
	//getting the string table section address
	strSectionContent := content[sections[header.E_shstrndx].Sh_offset : sections[header.E_shstrndx].Sh_offset+sections[header.E_shstrndx].Sh_size]

	for i := 0; i < int(header.E_shnum); i++ {
		strStart := int(sections[i].Sh_name)
		strEnd := bytes.IndexByte(strSectionContent[strStart:], 0)
		sectionNames[i] = string(strSectionContent[strStart : strStart+strEnd])
	}

	var textSection []byte
	var textStart uint64
	var textEnd uint64
	execSectionBefore := false
	var firstNotExecSectionInd int
	var textInd int
	for i := 0; i < int(header.E_shnum); i++ {
		if !execSectionBefore && sections[i].Sh_flags&0x4 == 0x4 {
			execSectionBefore = true
		}
		if execSectionBefore && sections[i].Sh_flags&0x4 != 0x4 {
			execSectionBefore = false
			firstNotExecSectionInd = i
		}

		if sectionNames[i] == ".text" {
			textInd = i
			textStart = sections[i].Sh_offset
			textEnd = textStart + sections[i].Sh_size
			textSection = content[textStart:textEnd]
		}
	}

	encryptionKey := args[1]
	encryptedText := encrypt(textSection, encryptionKey)

	//overwrite .text section with "encrypted" data
	for i := 0; i < len(textSection); i++ {
		content[int(textStart)+i] = encryptedText[i]
	}

	newEntryAddr := sections[firstNotExecSectionInd-1].Sh_addr + sections[firstNotExecSectionInd-1].Sh_size

	newEntry := toByteArray(newEntryAddr)

	shellcode := getShellcode(encryptionKey, len(textSection), int(newEntryAddr), int(sections[textInd].Sh_addr-(sections[textInd].Sh_addr%0x1000)), int(sections[textInd].Sh_addr), int(header.E_entry))
	lastExecSectionEnd := sections[firstNotExecSectionInd-1].Sh_offset + sections[firstNotExecSectionInd-1].Sh_size
	emptySpaceLen := sections[firstNotExecSectionInd].Sh_offset - lastExecSectionEnd

	if emptySpaceLen < uint64(len(shellcode)) {
		fmt.Println("Not enough space for the shellcode :(")
		return
	}

	//overwrite the file with payload
	for i := 0; i < len(shellcode); i++ {
		content[lastExecSectionEnd+uint64(i)] = shellcode[i]
	}

	//overwrite the entry point
	for i := 0; i < 8; i++ {
		content[i+24] = newEntry[i]
	}

	err = os.WriteFile("./"+args[0]+".pack", content, 0744)
	if err != nil {
		fmt.Println(err)
	}
}
