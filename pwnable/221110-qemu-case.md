# VM escape-QEMU Case Study

## 0x00 Intro

一句话说明虚拟机逃逸漏洞利用其实就是：

> 利用qemu代码实现上的漏洞去起一个`/bin/sh`什么的（当然执行计算器也是可以的）

问题是我们在guest虚拟机里面，我们怎么控制那个`/bin/sh`呢，那就是通过共享内存交换数据（传递我们的命令到共享内存，最终传递给shell，之后将shell命令的执行结果放入共享内存传递回来guest虚拟机），从而实现在guest虚拟机控制qemu启动的`/bin/sh`。

这个案例讲的是CVE-2015-5165 (信息泄露漏洞) and CVE-2015-7504 (堆溢出漏洞)

## 0x01 KVM/QEMU Overview

KVM（Kernel Virtual Machine）是Linux的一个内核驱动模块，它能够让Linux主机成为一个Hypervisor（虚拟机监控器）。

QEMU（quick emulator)本身并不包含或依赖KVM模块，而是一套由Fabrice Bellard编写的模拟计算机的free软件。QEMU虚拟机是一个纯软件的实现，可以在没有KVM模块的情况下独立运行，但是性能比较低。QEMU使用了KVM模块的虚拟化功能，为自己的虚拟机提供硬件虚拟化加速以提高虚拟机的性能。

### 1.1 Environment 

git clone下来后需要回退到漏洞版本

下面编译成x86_64，并且启用调试

```bash
git clone git://git.qemu-project.org/qemu.git
git checkout bd80b59
mkdir -p bin/debug/native
cd bin/debug/native
../../../configure --target-list=x86_64-softmmu --enable-debug --disable-werror
make
```

之后使用qemu-img来生成一个qcow2系统文件

````bash
./qemu-img create -f qcow2 ubuntu.qcow2 20G
sudo chmod 777 /dev/kvm
````

之后对qcow2系统文件中的系统进行安装

> 其中ubuntu16.iso是自己下载的

````bash
./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -m 2048 -hda ./ubuntu.qcow2 -cdrom '/home/mark/vm/ubuntu16.iso'
````

安装完成后就获得了一个有系统的qcow2文件，我们分配2GB的内存并创建两个网络接口卡：RTL8139和PCNET，同时创建tap接口连接虚拟机和主机：

````bash
 sudo tunctl -t tap0 -u `whoami`
 sudo ifconfig tap0 192.168.2.1/24
./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -m 2048 -display vnc=:89 \
   -netdev user,id=t0, -device rtl8139,netdev=t0,id=nic0 \
   -netdev user,id=t1, -device pcnet,netdev=t1,id=nic1 \
   -drive file=/home/mark/Desktop/qemu/bin/debug/native/ubuntu.qcow2,format=qcow2,if=ide,cache=writeback \
   -redir tcp:5022::22
````

添加这个参数`-redir tcp:5022::22`映射ssh端口，我们连接5022即可连接qemu里面的ssh

如果想使用GDB调试

````bash
gdb --args ./x86_64-softmmu/qemu-system-x86_64 -enable-kvm -m 2048   -netdev user,id=t0, -device rtl8139,netdev=t0,id=nic0    -redir tcp:5022::22    -netdev user,id=t1, -device pcnet,netdev=t1,id=nic1    -drive file=/home/mark/Desktop/qemu/bin/debug/native/ubuntu.qcow2,format=qcow2,if=ide,cache=writeback
````

### 1.2 QEMU Memory Layout

guest虚拟机的物理内存实际上是qemu程序mmap出来的一块private属性的虚拟内存。而且PROT_EXEC这个标志在这个虚拟内存中是不启用的

下面作者的图比较直观

![QEMU Memory Layout](http://pic.giantbranch.cn/pic/1561273670649.jpg)

此外，QEMU为BIOS和ROM保留了一个内存区域。 这些映射在QEMU映射文件中可用：

````
root@ubuntu:/home/mark# cat /proc/3481/maps
55bb934ac000-55bb93a4c000 r-xp 00000000 08:01 2127821                    /home/mark/Desktop/qemu/bin/debug/native/x86_64-softmmu/qemu-system-x86_64
55bb93c4b000-55bb93d15000 r--p 0059f000 08:01 2127821                    /home/mark/Desktop/qemu/bin/debug/native/x86_64-softmmu/qemu-system-x86_64
55bb93d15000-55bb93d93000 rw-p 00669000 08:01 2127821                    /home/mark/Desktop/qemu/bin/debug/native/x86_64-softmmu/qemu-system-x86_64
55bb93d93000-55bb94202000 rw-p 00000000 00:00 0 
55bb95758000-55bb97186000 rw-p 00000000 00:00 0                          [heap]
7f22937ff000-7f2293800000 ---p 00000000 00:00 0 
7f2293800000-7f2294000000 rw-p 00000000 00:00 0 
7f2294000000-7f2314000000 rw-p 00000000 00:00 0 

					......												[other shared libs]

7f23266a6000-7f23266a9000 rw-s 00000000 00:0e 11411                      anon_inode:kvm-vcpu:0
7f23266a9000-7f23266b0000 r--s 00000000 08:01 1977540                    /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
7f23266b0000-7f23266b1000 r--p 00029000 08:01 786525                     /lib/x86_64-linux-gnu/ld-2.27.so
7f23266b1000-7f23266b2000 rw-p 0002a000 08:01 786525                     /lib/x86_64-linux-gnu/ld-2.27.so
7f23266b2000-7f23266b3000 rw-p 00000000 00:00 0 
7ffdcf24e000-7ffdcf26f000 rw-p 00000000 00:00 0                          [stack]
7ffdcf3d0000-7ffdcf3d3000 r--p 00000000 00:00 0                          [vvar]
7ffdcf3d3000-7ffdcf3d4000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
````

由于我们给他分配了2GB内存，也就是0x80000000

![](https://pic1.imgdb.cn/item/636cf35216f2c2beb1681ed9.png)

### 1.3 Address Translation

在QEMU中存在两个翻译层：Guest Virtual Address → Guest Physical Address → Host Virtual Address

- 从Guest虚拟地址到Guest物理地址。 在我们的利用中，我们需要配置需要DMA访问的网卡设备。 例如，我们需要提供Tx / Rx缓冲区的**物理地址**以正确配置网卡设备。
- 从Guest物理地址到QEMU的虚拟地址空间。 在我们的攻击中，我们需要注入伪造的结构，并在**QEMU的虚拟地址空间**中获得其精确地址。

在x64系统上，虚拟地址由页偏移量（位0-11）和页码组成。 在linux系统上，具有CAP_SYS_ADMIN特权的用户空间进程能够使用页面映射文件（pagemap ）找出虚拟地址和物理地址的映射。 页面映射文件为每个虚拟页面存储一个64位值，其中`physical_address = PFN * page_size + offset`

相关代码：

````c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

int fd;
// 获取页内偏移
uint32_t page_offset(uint32_t addr)
{
	// addr & 0xfff
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;

    printf("pfn_item_offset : %p\n", (uintptr_t)addr >> 9);
    offset = ((uintptr_t)addr >> 9) & ~7;

    //一开始除以 0x1000  （getpagesize=0x1000，4k对齐，而且本来低12位就是页内索引，需要去掉），即除以2**12, 这就获取了页号了，
    //pagemap中一个地址64位，即8字节，也即sizeof(uint64_t)，所以有了页号后，我们需要乘以8去找到对应的偏移从而获得对应的物理地址
    //最终  vir/2^12 * 8 = (vir / 2^9) & ~7 
    //这跟上面的右移9正好对应，但是为什么要 & ~7 ,因为你  vir >> 12 << 3 , 跟vir >> 9 是有区别的，vir >> 12 << 3低3位肯定是0，所以通过& ~7将低3位置0
    // int page_size=getpagesize();
    // unsigned long vir_page_idx = vir/page_size;
    // unsigned long pfn_item_offset = vir_page_idx*sizeof(uint64_t);

    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    // 确保页面存在——page is present.
    if (!(pme & PFN_PRESENT))
        return -1;
    // physical frame number 
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

int main()
{
    uint8_t *ptr;
    uint64_t ptr_mem;
    
    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    
    ptr = malloc(256);
    strcpy(ptr, "Where am I?");
    printf("%s\n", ptr);
    ptr_mem = gva_to_gpa(ptr);
    printf("Your physical address is at 0x%"PRIx64"\n", ptr_mem);

    getchar();
    return 0;
}
````

具体可以看我的这一篇文章：[Document (mark0519.com)](https://blog.mark0519.com/#/pwnable/221108-gva2gpa)

