# Kernel basic 环境依赖

> 用户态玩累了不如来看看内核QwQ

前段时间笔者格式化了自己的电脑，以前配置的虚拟机数据也都没有备份，同时恰好Ubuntu22.04也推出了，不如整个新的Ubuntu然后顺便学习下或者说尝试整下kernel的环境。

## 0x00 编译内核镜像（bzImage）

### I. 下载源码

kernel内核官网，可以下载最新版本镜像：[The Linux Kernel Archives](https://cdn.kernel.org/)

kernel内核官网其他版本镜像下载地址：[Index of /pub/linux/kernel/](https://cdn.kernel.org/pub/linux/kernel/)

使用`wegt`或者浏览器直接下载都可以，这里笔者选择下载的版本为`linux-5.11.tar.xz`

浏览器访问 https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.11.tar.xz

或者 `wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.11.tar.xz`

### II. 编辑配置选项

下载完成解压之后，进入文件夹并进行配置编译选项

```shell
make menuconfig
```

保证勾选如下配置（默认都是勾选了的）：

- Kernel hacking —> Kernel debugging
- Kernel hacking —> Compile-time checks and compiler options —> Compile the kernel with debug info
- Kernel hacking —> Generic Kernel Debugging Instruments –> KGDB: kernel debugger
- kernel hacking —> Compile the kernel with frame pointers

一般来说不需要有什么改动，直接保存退出即可。

### III. 开始编译

运行编译命令

```shell
make bzImage
```

也可以使用`-j4`加速编译

```shell
make bzImage -j4
```

#### i. 遇到的报错

编译过程中笔者编译遇到的错误：

1. 报错：`make[1]: *** No rule to make target 'debian/canonical-certs.pem', needed by 'certs/x509_certificate_list'.  Stop.`

解决方法：执行`scripts/config --disable SYSTEM_TRUSTED_KEYS`

2. 报错：`BTF: .tmp_vmlinux.btf: pahole (pahole) is not available`

解决方法：执行：`sudo apt install dwarves`

最后编译完成

![](https://pic.imgdb.cn/item/62697338239250f7c5c0b8e6.png)

#### ii. vmlinux ： 原始内核文件

编译完成之后位于当前目录下

```bash
mark@mark:~/Desktop/Kernel/linux-5.11$ file vmlinux
vmlinux: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=1acd5799c90f7dffc3c73b539732dd51e2199e74, with debug_info, not stripped
```

vmlinux即是真正的编译出来的无压缩的内核文件

#### iii. bzImage ： 压缩内核镜像

编译完成之后位于`./arch/x86/boot/`

```bash
mark@mark:~/Desktop/Kernel/linux-5.11/arch/x86/boot$ file bzImage 
bzImage: Linux kernel x86 boot executable bzImage, version 5.11.0 (mark@mark) #2 SMP Thu Apr 28 00:41:11 CST 2022, RO-rootFS, swap_dev 0XA, Normal VGA
```

zImage是vmlinux经过gzip压缩后的文件。

bzImagebz表示“big zImage”，不是用bzip2压缩的，而是要偏移到一个位置，使用gzip压缩的。

两者的不同之处在于，zImage解压缩内核到低端内存(第一个 640K)，bzImage解压缩内核到高端内存(1M以上)。

如果内核比较小，那么采用zImage或bzImage都行，如果比较大应该用bzImage。

## 0x01 安装Busybox

Busybox 是一个集成了三百多个最常用Linux命令和工具的软件，包含了例如ls、cat和echo等一些简单的工具

后续构建磁盘镜像我们需要用到busybox，常见的内核pwn中加载的基本都是busybox。

### I. 下载源码

busybox官网：[Index of /downloads (busybox.net)](https://busybox.net/downloads/)

笔者这里选择下载`busybox-1.33.0.tar.bz2`这个版本

### II. 编译配置选项

同样解压完成之后，进入文件夹进行编译前的配置
```shell
make menuconfig
```

需要勾选 Settings —> Build static binary file (no shared lib)

### III. 开始编译

运行编译命令

```bash
make install
```

速度会比编译内核快很多

编译完成后会生成一个`_install`目录，接下来我们将会用它来构建我们的磁盘镜像

## 0x02 构建磁盘镜像

### I. 建立文件系统

#### i. 初始化文件系统

一些初始化操作

```bash
$ cd _install
$ mkdir -pv {bin,sbin,etc,proc,sys,home,lib64,lib/x86_64-linux-gnu,usr/{bin,sbin}}
$ touch etc/inittab
$ mkdir etc/init.d
$ touch etc/init.d/rcS
$ chmod +x ./etc/init.d/rcS
```

#### ii. 初始化脚本

首先配置`etc/inttab`，写入如下内容：

```
::sysinit:/etc/init.d/rcS
::askfirst:/bin/ash
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
```

在上面的文件中指定了系统初始化脚本，因此接下来配置`etc/init.d/rcS`，写入如下内容：

```bash
#!/bin/sh
mount -t proc none /proc
mount -t sys none /sys
/bin/mount -n -t sysfs none /sys
/bin/mount -t ramfs none /dev
/sbin/mdev -s
```

主要是配置各种目录的挂载

也可以在根目录下创建`init`文件，写入如下内容：

```bash
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev

exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

最后添加可执行权限：

```bash
$ chmod +x ./init
```

#### iii. 配置用户组

```bash
$ echo "root:x:0:0:root:/root:/bin/sh" > ./etc/passwd
$ echo "ctf:x:1000:1000:ctf:/home/ctf:/bin/sh" >> ./etc/passwd
$ echo "root:x:0:" > ./etc/group
$ echo "ctf:x:1000:" >> ./etc/group
$ echo "none /dev/pts devpts gid=5,mode=620 0 0" > ./etc/fstab
```

在这里建立了两个用户组`root`和`ctf`，以及两个用户`root`和`ctf`

#### iv. 配置glibc库

从本地的`/lib/x86_64-linux-gnu/`文件夹下复制需要的libc文件到对应目录即可

### II. 文件系统打包

使用如下命令打包文件系统

```bash
$ find . | cpio -o --format=newc > ../../rootfs.cpio
```

也可以这么写

```bash
$ find . | cpio -o -H newc > ../../core.cpio
```

> 当然打包的位置随意

## 0x03 使用qemu运行内核

首先讲我们编译出来的bzImage和rootfs.cpio放到同一个目录下

之后编写启动脚本`boot.sh`

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 256M \
    -kernel ./bzImage \
    -initrd  ./rootfs.cpio \
    -monitor /dev/null \
    -append "root=/dev/ram rdinit=/sbin/init console=ttyS0 oops=panic panic=1 loglevel=3 quiet nokaslr" \
    -cpu kvm64,+smep \
    -smp cores=2,threads=1 \
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
    -nographic \
    -s
```

部分参数说明如下：

- `-m`：虚拟机内存大小

- `-kernel`：内存镜像路径

- `-initrd`：磁盘镜像路径

- `-append`：附加参数选项
  - `nokalsr`：关闭内核地址随机化，方便我们进行调试
  - `rdinit`：指定初始启动进程，`/sbin/init`进程会默认以`/etc/init.d/rcS`作为启动脚本
  - `loglevel=3 `& `quiet`：不输出log
  - `console=ttyS0`：指定终端为`/dev/ttyS0`，这样一启动就能进入终端界面
  
- `-monitor`：将监视器重定向到主机设备`/dev/null`，这里重定向至null主要是防止CTF中被人给偷了qemu拿flag

- `-cpu`：设置CPU安全选项，在这里开启了smep保护

- `-s`：相当于`-gdb tcp::1234`的简写（也可以直接这么写），后续我们可以通过gdb连接本地端口进行调试

之后运行脚本，就可以看到我们自己的内核跑起来了 ╰(*°▽°*)╯

![](https://pic.imgdb.cn/item/6269817c239250f7c5d94046.png)

## 0x04 gdb调试内核

### I. 符号表导入

使用dbg启动编码编译出来的vmlinux（开启了debug info选项）

```bash
$ gdb  vmlinux
```

### II. remote链接

之前编写boot.sh的时候使用了`-s`参数，也就是映射到本地的1234端口上，所以在gdb里远程链接使用

```bash
pwndbg> set architecture i386:x86-64
pwndbg> target remote localhost:1234
```

![](https://pic.imgdb.cn/item/6269fa0e239250f7c563cd7d.png)

### III. 解压bzImage获得vmlinux

有的CTF题目只会提供bzImage文件，我们可以用下面的脚本解压出vmlinux文件

````bash
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
    # Use readelf to check if it's a valid ELF
    # TODO: find a better to way to check that it's really vmlinux
    #       and not just an elf
    readelf -h $1 > /dev/null 2>&1 || return 1

    cat $1
    exit 0
}

try_decompress()
{
    # The obscure use of the "tr" filter is to work around older versions of
    # "grep" that report the byte offset of the line instead of the pattern.

    # Try to find the header ($1) and decompress from here
    for    pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
    do
        pos=${pos%%:*}
        tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
        check_vmlinux $tmp
    done
}

# Check invocation:
me=${0##*/}
img=$1
if    [ $# -ne 1 -o ! -s "$img" ]
then
    echo "Usage: $me <kernel-image>" >&2
    exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
````

解压命令

```bash
$ ./extract-vmlinux ./bzImage > vmlinux
```

### IV. 寻找gadget

ROPgadget太慢了，笔者更喜欢用ropper

```bash
$ ropper --file ./vmlinux --nocolor > gadget.txt
```

一般出来大概有个几十MB

### V. 内核调试

gdb链接上之后，我们还需要手动加载一些载入地址来方便调试

首先通过读取 `/sys/module/模块名/sections/` 目录下对应的文件获取对应 section 在内核中的载入地址，例如我们调试时需要用到 `.text`、`.data`、`.bss` 这三个段的数据

```bash
$ cat /sys/module/module_name/sections/.text
$ cat /sys/module/module_name/sections/.data
$ cat /sys/module/module_name/sections/.bss
```

之后在使用 gdb 连接上 qemu 后，使用 `add-symble-file` 命令载入内核模块信息，默认指定为 `.text` 段

```bash
$ pwngdb>add-symbol-file ./module_name.ko 0xffffffffc0002000 -s .data 0xffffffffc0004000 -s .bss 0xffffffffc0004480
```

之后就可能正常调试内核了。

