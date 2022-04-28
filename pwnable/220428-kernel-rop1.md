# Kernel ROP basic

> 会内核pwn的人看起来就像带黑阔 (*￣3￣)╭

ROP即`返回导向编程`（Return-oriented programming），是一种比较熟悉的一种攻击方式——通过复用代码片段的方式控制程序执行流。

**内核态的 ROP 与用户态的 ROP 一般无二，只不过利用的 gadget 变成了内核中的 gadget，所需要构造执行的 ropchain 由**`system("/bin/sh")`**变为了**`commit_creds(prepare_kernel_cred(NULL))`

当成功执行 `commit_creds(prepare_kernel_cred(NULL))` 之后，当前线程的 cred 结构体便变为 init 进程的 cred 的拷贝，我们也就获得了 root 权限，此时在用户态起一个 shell 便能获得 root shell。

## 0x00 保存状态

一般情况下，我们的exploit需要在内核中完成提权，但最终还是要返回用户态来获得一个有root权限的shell。

因此，在exploit进入内核之前，我们需要**手动**保存当前的状态，也就是**保存当前寄存器的值到内核栈**上，便于之后我们返回用户态。

一个常见的模板：

````c
size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}
````

> 方便起见，使用了内联汇编，编译时需要指定参数：`-masm=intel`

## 0x01 返回用户态

程序返回用户态的过程，简单来说就是

- `swapgs`指令恢复用户态GS寄存器
- `sysretq`或者`iretq`恢复到用户空间

那么我们只需要在内核中找到相应的gadget并执行`swapgs;iretq`就可以成功着陆回用户态

通常的ROP需要下面的链子：

```c
swapgs;
iretq;
user_shell_addr;
user_cs;
user_eflags; //64bit user_rflags
user_sp;
user_ss;
```

## 0x02 KPTI bypass

### I. KPTI介绍

**KPTI-Kernel Page Table Isolation：内核页表隔离**

用户态不可看到内核态的页表；内核态不可执行用户态的代码（模拟）

KPTI 机制最初的主要目的是为了缓解 KASLR 的绕过以及 CPU 侧信道攻击。

在 KPTI 机制中，内核态空间的内存和用户态空间的内存的隔离进一步得到了增强。

- 内核态中的页表包括用户空间内存的页表和内核空间内存的页表。
- 用户态的页表只包括用户空间内存的页表以及必要的内核空间内存的页表，如用于处理系统调用、中断等信息的内存。

在 x86_64 的 PTI 机制中，内核态的用户空间内存映射部分被全部标记为不可执行。也就是说，之前不具有 SMEP 特性的硬件，如果开启了 KPTI 保护，也具有了类似于 SMEP 的特性。此外，SMAP 模拟也可以以类似的方式引入，只是现在还没有引入。因此，在目前开启了 KPTI 保护的内核中，如果没有开启 SMAP 保护，那么内核仍然可以访问用户态空间的内存，只是不能跳转到用户态空间执行 Shellcode。

Linux 4.15 中引入了 KPTI 机制，并且该机制被反向移植到了 Linux 4.14.11，4.9.75，4.4.110。

### II. ROP中的KPTI绕过

返回用户态之后，我们也要将页表切换回用户态的页表。

众所周知 Linux 采用**四级页表**结构（PGD->PUD->PMD->PTE），而 CR3 控制寄存器用以存储当前的 PGD 的地址，因此在开启 KPTI 的情况下用户态与内核态之间的切换便涉及到 CR3 的切换，为了提高切换的速度，内核将内核空间的 PGD 与用户空间的 PGD 两张页全局目录表放在一段连续的内存中（两张表，一张一页4k，总计8k，内核空间的在低地址，用户空间的在高地址），这样**只需要将 CR3 的第 13 位取反便能完成页表切换的操作**

除了在系统调用入口中将用户态页表切换到内核态页表的代码外，内核也相应地在`arch/x86/entry/entry_64.S` 中提供了一个用于完成内核态页表切换回到用户态页表的函数 `swapgs_restore_regs_and_return_to_usermode`，地址可以在 `/proc/kallsyms` 中获得

这个函数大概实现了下面的操作

```assembly
mov        rdi, cr3
or         rdi, 0x1000
mov        cr3, rdi
pop        rax
pop        rdi
swapgs
iretq
```

所以我们需要构造的ROP链变成了：

````c
swapgs_restore_regs_and_return_to_usermode
0 // padding
0 // padding
user_shell_addr
user_cs
user_rflags
user_sp
user_ss
````

## 0x03 例题

> 强网杯2018 - core

