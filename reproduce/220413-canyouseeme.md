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
