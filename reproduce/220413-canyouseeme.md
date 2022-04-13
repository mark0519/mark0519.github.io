# can_you_see_me

> Category: PWN
>
> Date: 2022/04/13
>
> Authorship: pwnhub.cn
>
> Attachment: [challenges/pwnhub/can_you_see_me](https://github.com/mark0519/challenges/tree/main/pwnhub/22.03.19)

## 0x00 知识点

1. house of spirit 
2. unlink + off by null 
3. SROP, 伪造IO_FILE结构体,通过_IO_FILE_plus的chain字段进行伪造
4. payload 长度有限时,需要利用一些特殊的gadget,以及寄存器的值,构造read读入 更长的payload 
5. setcontext绕过沙盒,使用orw拿flag 
5. close(1)后,程序仍然可以交互,利用stderr打印flag 
6. 限制申请次数时地利用, 本题限制了只能申请 8次

## 0x01 解题分析

题目是libc2.23下的UAF的菜单题，其中add_small的时候存在offbynull的漏洞，于此同时该程序未开启PIE保护，程序bss段地址固定。

同时该程序存在可以泄露libc地址的```gift()```函数，但要求的条件是bss段上0x602290处的内容为 0xF1E2D3C4B5A69788。

但是调用完gift函数之后程序会close(1)，也就是关闭标准输出。

且程序开始seccomp沙盒，禁用execve等函数。

最后程序会不停检查malloc_hook，free_hook，realloc_hook等hook部分，如果检查到不为空则程序直接退出。

### 1. Unlink在bss上申请堆

需要注意的是，该程序没有idx的说法，用户只能控制一大一小两个chunk：分别是大小可控但必须小于0x70的small_chunk和大小固定的big_chunk。

同时该程序存在可以泄露libc地址的```gift()```函数，但要求的条件是bss段上0x602290处的内容为 0xF1E2D3C4B5A69788，所以我们第一步考虑在bss上制造一个可控的chunk，由于程序没有开启PIE保护所以我们可以考虑使用unlink和house of spirit 的手法，unlink的利用又正好可以用上offbynull。

对于glibc-2.23的程序来说，绕过unlink保护我们需要绕过检查：

````c
FD == P->fd
BK == P->bk
````

简单来说，glibc-2.23在利用unlink宏的时候，会检查被合并的chunk是否处于一个双向链表中。

一个正常的unlink过程：

````
        |---------------------|
addr1-> |                 size|  <- free  chunk0
        |---------------------|
        |       fd|         bk|
        |---------------------|
        |data...              |
        |---------------------|
addr2-> |   p_size|       size|  <-alloced chunk1
        |---------------------|
        |data...              |
        |---------------------|

````

对于上面在双向链表bins中的chunk0，他的fk和bk在双向bins中的状态为：

````c
|----------|===>|   fd   |===>|      fd      |
|main_arena|    | chunk0 |    | other_chunk  | 
|----------|<===|   bk   |<===|      bk      |
````

他的fd指针和bk指针一定满足：

````c
fd->bk == addr1
bk->fd == addr1
````

所以，如果我们想利用unlink，那么被我们合并的chunk，例如这里的chunk0，他首先要利用offbynull来溢出到下一个chunk1的size位置，吧prev_inuse位置于0，同时构造好prev_size位，再然后，我们要伪造chunk0的fd和bk。

所以我们可以首先malloc_small(0x28)，这样来得到一个0x31的chunk，之后malloc_big()得到一个0x121的chunk，再这个small_chunk中，我们填入p64(0)+p64(0x21)+p64(fd)+p64(bk)，这样再这个0x31的chunk中伪造一个看起来被free的0x21的chunk。之后溢出到大chunk的prev_size位和size位，其中prev_size填入0x20，size溢出null字节覆盖成0x100，同时要注意申请大chunk的时候再0x100的位置伪造好下一个0x20的chunk，方式修改size之后heap结构混乱。

效果如下：

![](https://pic.imgdb.cn/item/6256c496239250f7c581b9af.png)

这里红色方框中就是伪造的size=0x21的chunk，橙色部分是offbynull溢出的效果，最下面紫色部分是为了防止heap混乱再填充big_chunk中时写入的数据，这样big_chunk的size被覆盖之后（0x121 ==> 0x100）,heap结构仍然正常。

值得注意的是，这里红框中的0x1111和0x2222应该被写入fd和bk，上文提到过，unlink宏存在检查：

````
FD == P->fd
BK == P->bk
````

所以这里的fd和bk我们不能随意填写，而是需要仔细构造。

一开始我们就提到了，程序没有开启PIE保护而导致bss段地址固定，同时程序在一开始让我们输入name和message都会保存在bss段上，同时，small_chunk和big_chunk的指针也会保存在bss端上，让我们来看看现在bss段上有些啥：

![](https://pic.imgdb.cn/item/6256c6d6239250f7c585c758.png)

红色部分是输入的name，紫色部分是输入的message，橙色部分是small_chunk的指针，绿色部分是big_chunk的指针。

所以，为了满足unlink的条件，我们不妨利用上bss段上的这两个指针，这里我们利用small_chunk的指针，

small_chunk的指针位于0x602298，这样如果我们在伪造的0x21的chunk中令:

````c
fd = 0x602298 - 0x18 = 0x602280
bk = 0x602298 - 0x10 = 0x602288
````

这样再释放0x100的chunk进行unlink的时候，进行检查会变成：

首先检查fd ， fd=0x602280，这样位于0x602280的chunk的bk位于0x602280+0x18=0x602298，

再检查bk，bk=0x602288，这样位于0x602288的chunk的fd位于0x602288+0x10=0x602298，

这样我们使得了fd -> bk == bk -> fd，从而绕过了检查。

最后理论上就可以修改这里的small_chunk指针为&small_chunk-0x18，这也是我们unlink的目的。

之后进行unlink操作，查看效果：

![](https://pic.imgdb.cn/item/6256cb6d239250f7c58e50ba.jpg)

可以看到我们的small_chunk已经被修改为0x602280。而这是一个位于bss段的地址。
同时我们想到，再输入name和message的时候我们是可以往bss段写上数据的，这里竟然我们可以控制small_chunk的地址，我们就需要再输入name和message的时候提前布置好size位，方面后面的利用。

这里我们就往0x602278（0x602280-8）的地方提前一个0x71当作size位，这样unlink之后就可以释放small_chunk，然后再申请回来，这样我们就可以修改更多bss段的地址，当然包括修改我们的需要调用```gift()```函数来泄露libc的0x602290处。

效果：

![](https://pic.imgdb.cn/item/6256db2e239250f7c5aabf26.jpg)

### 2. 泄露libc

由于程序提供了```gift()```函数，泄露libc并不困难，只要利用前面提到的unlink来做到在bss段上的任意写，在0x602290填上要求的数据，之后调用```gift()```函数就可以泄露puts的真实地址，减去偏移就可以得到libc基地址。

但是要注意的是，调用```gift()```函数会导致程序关闭标准输出：```close(1); ```,
