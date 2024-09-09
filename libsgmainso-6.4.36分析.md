/**
 * Author: sp00f
 * 本人聲明： 該項目僅用於學習和交流目的，不能用於其他目的，否則後果自負；
 * 另外該項目所有權僅屬於我個人，你可以下載或者fork該項目，但不能用於其他目的（如發表文章、出書、投稿等），否則必究。
 * 你可以吐槽我，不过还是希望尊重我的辛苦成果，有不对的地方，可以指出，大家互相探讨
 * 对于逆向我也是个小学生，水平有限，还请大佬们一笑而过
 * 出于时间考虑，我分析完之后，没有对调试过程返回来看，但应该大致描述清楚了
 * 如果纰漏，请见谅
 *
*/


libsgmainso-6.4.36邏輯分析

//////////////////////////////////////////////////////////////

難點：

動態跳轉
動態生成參數，參數變形
函數隱藏（需要通過一個類似的梉跳過去，函數地址加密）
函數前面加一段垃圾代碼
字符串加密
部分關鍵代碼存在llvm混淆
垃圾代碼，靜態分析對抗，擾亂ida分析
多種加密算法
核心函數如進入到do_command_native的函數不是連續的，函數的連續性被記錄到一系列的
結構體中，下一個塊需要的獲取需要重新執行do_command_inner


LOAD:0000B110 JNI_OnLoad
LOAD:0000B110
LOAD:0000B110 var_4           = -4
LOAD:0000B110 07 B5          PUSH            {R0-R2,LR}
LOAD:0000B112 07 A1          ADR             R1, 0xB130 // B130
LOAD:0000B114 09 00          MOVS            R1, R1
LOAD:0000B116 05 39          SUBS            R1, #5 // B130 - 0X5 = B12B
LOAD:0000B118 00 00          MOVS            R0, R0
LOAD:0000B11A 08 00          MOVS            R0, R1 // B12B
LOAD:0000B11C 12 00          MOVS            R2, R2
LOAD:0000B11E 10 30          ADDS            R0, #0x10 // B12B + 0X10 = B13B
LOAD:0000B120 03 90          STR             R0, [SP,#0xC] // SP + 0XC = R0 = B13B
LOAD:0000B122 07 BD          POP             {R0-R2,PC} // PC = sp + 0xc = B13B, thumb指令跳转到0000B13A 

执行完上述代码，r0,r1,r2,lr值不变，变的仅仅是pc，cpu会马上执行pc处的指令

=================================================================================================
代码段共56处匹配这样的特征，想办法patch这样的逻辑
patch 后
LOAD:0000B110 JNI_OnLoad
LOAD:0000B122                 B               loc_B13A
===================================================================================================

因为是thumb指令，地址起始奇数
LOAD:0000B13A ; ---------------------------------------------------------------------------
特徵
LOAD:0000B13A                 CODE16
LOAD:0000B13A                 PUSH            {R0,R1,LR}
LOAD:0000B13C                 LDR             R0, =8
LOAD:0000B13E                 LDR             R1, loc_B140 // 沒有意義， nop掉
LOAD:0000B140
LOAD:0000B140 loc_B140     
LOAD:0000B140                 BLX             sub_494C    /// 分发器
LOAD:0000B140 ; ---------------------------------------------------------------------------
LOAD:0000B144 dword_B144      DCD 8            
-------------------------------------------------------------------------------------------
跳轉表，共40個跳轉， 計算pc時的纍加值：               
LOAD:0000B144                                            
LOAD:0000B144                                            ;第一個index = 8
LOAD:0000B144                                            ; 找到8對應的偏移，它下一個index即下一個邏輯
LOAD:0000B148 A8 00 00 00                 DCD 0xA8       ; b1ec
LOAD:0000B14C BC 00 00 00                 DCD 0xBC       ; b200
LOAD:0000B150 CC 00 00 00                 DCD 0xCC       ; b120
LOAD:0000B154 E0 00 00 00                 DCD 0xE0       ; b224
LOAD:0000B158 F0 00 00 00                 DCD 0xF0       ; b234
LOAD:0000B15C 00 01 00 00                 DCD 0x100      ; b244
LOAD:0000B160 10 01 00 00                 DCD 0x110      ; b254
LOAD:0000B164 20 01 00 00                 DCD 0x120      ; b264 偏移為8，表值為0x120，第一個對應lr + off = b144 + 0x120
LOAD:0000B168 34 01 00 00                 DCD 0x134      ; b278
LOAD:0000B16C 4C 01 00 00                 DCD 0x14C      ; b290
LOAD:0000B170 68 01 00 00                 DCD 0x168      ; b2ac
LOAD:0000B174 7C 01 00 00                 DCD 0x17C      ; b2c0
LOAD:0000B178 94 01 00 00                 DCD 0x194      ; b2d8
LOAD:0000B17C AC 01 00 00                 DCD 0x1AC      ; b2f0
LOAD:0000B180 D4 01 00 00                 DCD 0x1D4      ; b318
LOAD:0000B184 EC 01 00 00                 DCD 0x1EC      ; b330
LOAD:0000B188 08 02 00 00                 DCD 0x208      ; b34c
LOAD:0000B18C 24 02 00 00                 DCD 0x224      ; b368
LOAD:0000B190 40 02 00 00                 DCD 0x240      ; b384
LOAD:0000B194 68 02 00 00                 DCD 0x268      ; b3ac
LOAD:0000B198 7C 02 00 00                 DCD 0x27C      ; b3c0
LOAD:0000B19C 90 02 00 00                 DCD 0x290      ; b3d4
LOAD:0000B1A0 A4 02 00 00                 DCD 0x2A4      ; b3e0
LOAD:0000B1A4 B8 02 00 00                 DCD 0x2B8      ; b3fc
LOAD:0000B1A8 CC 02 00 00                 DCD 0x2CC      ; b410
LOAD:0000B1AC E0 02 00 00                 DCD 0x2E0      ; b424
LOAD:0000B1B0 FC 02 00 00                 DCD 0x2FC      ; b440
LOAD:0000B1B4 10 03 00 00                 DCD 0x310      ; b454
LOAD:0000B1B8 24 03 00 00                 DCD 0x324      ; b468
LOAD:0000B1BC 3C 03 00 00                 DCD 0x33C      ; b480
LOAD:0000B1C0 58 03 00 00                 DCD 0x358      ; b49c
LOAD:0000B1C4 6C 03 00 00                 DCD 0x36C      ; b4b0
LOAD:0000B1C8 90 03 00 00                 DCD 0x390      ; b4d4
LOAD:0000B1CC AC 03 00 00                 DCD 0x3AC      ; b4f0
LOAD:0000B1D0 C4 03 00 00                 DCD 0x3C4      ; b508
LOAD:0000B1D4 D8 03 00 00                 DCD 0x3D8      ; b51c
LOAD:0000B1D8 F0 03 00 00                 DCD 0x3F0      ; b534
LOAD:0000B1DC 14 04 00 00                 DCD 0x414      ; b558
LOAD:0000B1E0 28 04 00 00                 DCD 0x428      ; b56c
LOAD:0000B1E4 40 04 00 00                 DCD 0x440      ; b584
LOAD:0000B1E8 5C 04 00 00                 DCD 0x45C      ; b5a0
-------------------------------------------------------------------------------------------------------------
以第一次跳轉為例：
LOAD:0000494C sub_494C                              
LOAD:0000494C arg_8           =  8
LOAD:0000494C                 BIC             R1, LR, #1  // LR = B144 , 最低一位清零  R1 还是B144
//LOAD:0000B164    DCD 0x120
LOAD:00004950 00 11 91 E7     LDR  R1, [R1,R0,LSL#2] 	  // R1 = [B144 + 0x8 << 2] =  [B144 + 0X20] = [B164] = 0x120
LOAD:00004954                 ADD             R1, R1, LR  // R1 = B144 + 0x120 = B264
LOAD:00004958                 LDR             LR, [SP,#8] // LR = B144
LOAD:0000495C                 STR             R1, [SP,#8] // B264
LOAD:00004960 03 80 BD E8     LDMFD           SP!, {R0,R1,PC} // R0 = [SP], R1 = [SP + 4], PC = [SP + 8] 跳转到B264
隨便列舉幾個跳轉：
1 = 0xb264
2 = 0x1511c
3 = 0x24764
4 = 0x5f2ac
5 = 0x71e70
6 = 0x72dbc
7 = 0x9a14
...
---------------------------------------------------------------------------------------------
其他混淆跳轉輔助指令特徵：
LOAD:0000494C
LOAD:0000494C             ; =============== S U B R O U T I N E =======================================
LOAD:0000494C
LOAD:0000494C
LOAD:0000494C             dyna_pc                                 ; CODE XREF: j_dyna_pcj
LOAD:0000494C                                                     ; LOAD:loc_4C20p ...
LOAD:0000494C
LOAD:0000494C             arg_8           =  8
LOAD:0000494C
LOAD:0000494C 01 10 CE E3                 BIC             R1, LR, #1
LOAD:00004950 00 11 91 E7                 LDR             R1, [R1,R0,LSL#2] ; lr(最低位清零) + (r0 << 2)
LOAD:00004954 0E 10 81 E0                 ADD             R1, R1, LR
LOAD:00004958 08 E0 9D E5                 LDR             LR, [SP,#8]
LOAD:0000495C 08 10 8D E5                 STR             R1, [SP,#8]
LOAD:00004960 03 80 BD E8                 LDMFD           SP!, {R0,R1,PC} ; 1 = 0xb264
LOAD:00004960             ; End of function dyna_pc               ; 2 = 0x1511c
LOAD:00004960                                                     ; 3 = 0x24764
LOAD:00004960                                                     ; 4 = 0x5f2ac
LOAD:00004960                                                     ; 5 = 0x71e70
LOAD:00004960                                                     ; 6 = 0x72dbc
LOAD:00004960                                                     ; 7 = 0x9a14
LOAD:00004960                                                     ; ...
LOAD:00004964
LOAD:00004964             ; =============== S U B R O U T I N E =======================================
LOAD:00004964
LOAD:00004964             ; 完成pc = pc + 8
LOAD:00004964             ; 待彈出寄存器值為 lr + [lr]
LOAD:00004964             ; 目的是完成動態生成函數參數
LOAD:00004964
LOAD:00004964             dyna_mkarg                              ; CODE XREF: sub_4ADC:loc_4AE0j
LOAD:00004964                                                     ; LOAD:00004D16p ...
LOAD:00004964
LOAD:00004964             anonymous_0     =  0
LOAD:00004964             arg_C           =  0xC
LOAD:00004964             arg_10          =  0x10
LOAD:00004964
LOAD:00004964 01 00 CE E3                 BIC             R0, LR, #1
LOAD:00004968 00 10 90 E5                 LDR             R1, [R0]
LOAD:0000496C 01 10 90 E7                 LDR             R1, [R0,R1]
LOAD:00004970 04 E0 8E E2                 ADD             LR, LR, #4
LOAD:00004974 0C E0 8D E5                 STR             LR, [SP,#0xC] ; pc = lr + 4 ,下一條指令処
LOAD:00004978 10 10 8D E5                 STR             R1, [SP,#0x10] ; 後面pop 寄存器的值
LOAD:0000497C 03 C0 BD E8                 LDMFD           SP!, {R0,R1,LR,PC} ; pc =  pc + 8
LOAD:0000497C
LOAD:00004980
LOAD:00004980             ; =============== S U B R O U T I N E =======================================
LOAD:00004980
LOAD:00004980
LOAD:00004980             sub_4980                                ; CODE XREF: sub_4ABC:loc_4AC0j
LOAD:00004980
LOAD:00004980             arg_8           =  8
LOAD:00004980
LOAD:00004980 01 10 CE E3                 BIC             R1, LR, #1
LOAD:00004984 00 11 91 E7                 LDR             R1, [R1,R0,LSL#2]
LOAD:00004988 81 00 8E E0                 ADD             R0, LR, R1,LSL#1
LOAD:0000498C 08 E0 9D E5                 LDR             LR, [SP,#arg_8]
LOAD:00004990 08 00 8D E5                 STR             R0, [SP,#arg_8]
LOAD:00004994 03 80 BD E8                 LDMFD           SP!, {R0,R1,PC}
LOAD:00004994             ; End of function sub_4980
LOAD:00004994
LOAD:00004998
LOAD:00004998             ; =============== S U B R O U T I N E =======================================
LOAD:00004998
LOAD:00004998
LOAD:00004998             sub_4998                                ; CODE XREF: sub_4AC4:loc_4AC8j
LOAD:00004998                                                     ; LOAD:000098FCp ...
LOAD:00004998
LOAD:00004998             arg_8           =  8
LOAD:00004998
LOAD:00004998 01 00 CE E3                 BIC             R0, LR, #1
LOAD:0000499C 00 10 90 E5                 LDR             R1, [R0]
LOAD:000049A0 0E 10 81 E0                 ADD             R1, R1, LR
LOAD:000049A4 08 E0 9D E5                 LDR             LR, [SP,#arg_8]
LOAD:000049A8 08 10 8D E5                 STR             R1, [SP,#arg_8]
LOAD:000049AC 03 80 BD E8                 LDMFD           SP!, {R0,R1,PC}
LOAD:000049AC             ; End of function sub_4998
LOAD:000049AC
LOAD:000049B0
LOAD:000049B0             ; =============== S U B R O U T I N E =======================================
LOAD:000049B0
LOAD:000049B0
LOAD:000049B0             sub_49B0
LOAD:000049B0
LOAD:000049B0             arg_C           =  0xC
LOAD:000049B0             arg_10          =  0x10
LOAD:000049B0
LOAD:000049B0 01 00 CE E3                 BIC             R0, LR, #1
LOAD:000049B4 00 10 90 E5                 LDR             R1, [R0]
LOAD:000049B8 00 10 81 E0                 ADD             R1, R1, R0
LOAD:000049BC 04 E0 8E E2                 ADD             LR, LR, #4
LOAD:000049C0 0C E0 8D E5                 STR             LR, [SP,#arg_C]
LOAD:000049C4 10 10 8D E5                 STR             R1, [SP,#arg_10]
LOAD:000049C8 03 C0 BD E8                 LDMFD           SP!, {R0,R1,LR,PC}
LOAD:000049C8             ; End of function sub_49B0
LOAD:000049C8
LOAD:000049CC
LOAD:000049CC             ; =============== S U B R O U T I N E =======================================
LOAD:000049CC
LOAD:000049CC
LOAD:000049CC             sub_49CC
LOAD:000049CC
LOAD:000049CC             var_4           = -4
LOAD:000049CC
LOAD:000049CC 03 40 2D E9                 STMFD           SP!, {R0,R1,LR}
LOAD:000049D0 0E 10 A0 E1                 MOV             R1, LR
LOAD:000049D4 A1 10 A0 E1                 MOV             R1, R1,LSR#1
LOAD:000049D8 81 10 A0 E1                 MOV             R1, R1,LSL#1
LOAD:000049DC 01 00 A0 E1                 MOV             R0, R1
LOAD:000049E0 00 10 91 E5                 LDR             R1, [R1]
LOAD:000049E4 00 10 81 E0                 ADD             R1, R1, R0
LOAD:000049E8 00 10 91 E5                 LDR             R1, [R1]
LOAD:000049EC 08 10 8D E5                 STR             R1, [SP,#0xC+var_4]
LOAD:000049F0 04 E0 8E E2                 ADD             LR, LR, #4
LOAD:000049F4 03 80 BD E8                 LDMFD           SP!, {R0,R1,PC}
LOAD:000049F4             ; End of function sub_49CC
LOAD:000049F4
LOAD:000049F8
LOAD:000049F8             ; =============== S U B R O U T I N E =======================================
LOAD:000049F8
LOAD:000049F8
LOAD:000049F8             sub_49F8
LOAD:000049F8
LOAD:000049F8             arg_4           =  4
LOAD:000049F8
LOAD:000049F8 04 E0 9D E5                 LDR             LR, [SP,#arg_4]
LOAD:000049FC 04 00 8D E5                 STR             R0, [SP,#arg_4]
LOAD:00004A00 01 80 BD E8                 LDMFD           SP!, {R0,PC}
LOAD:00004A00             ; End of function sub_49F8
LOAD:00004A00
LOAD:00004A04
LOAD:00004A04             ; =============== S U B R O U T I N E =======================================
LOAD:00004A04
LOAD:00004A04
LOAD:00004A04             sub_4A04
LOAD:00004A04
LOAD:00004A04             arg_C           =  0xC
LOAD:00004A04             arg_10          =  0x10
LOAD:00004A04             arg_14          =  0x14
LOAD:00004A04
LOAD:00004A04 0E 10 A0 E1                 MOV             R1, LR
LOAD:00004A08 A1 10 A0 E1                 MOV             R1, R1,LSR#1
LOAD:00004A0C 81 10 A0 E1                 MOV             R1, R1,LSL#1
LOAD:00004A10 01 00 A0 E1                 MOV             R0, R1
LOAD:00004A14 00 10 91 E5                 LDR             R1, [R1]
LOAD:00004A18 00 10 81 E0                 ADD             R1, R1, R0
LOAD:00004A1C 00 00 91 E5                 LDR             R0, [R1]
LOAD:00004A20 04 10 91 E5                 LDR             R1, [R1,#4]
LOAD:00004A24 10 00 8D E5                 STR             R0, [SP,#arg_10]
LOAD:00004A28 14 10 8D E5                 STR             R1, [SP,#arg_14]
LOAD:00004A2C 04 E0 8E E2                 ADD             LR, LR, #4
LOAD:00004A30 0C E0 8D E5                 STR             LR, [SP,#arg_C]
LOAD:00004A34 03 40 BD E8                 LDMFD           SP!, {R0,R1,LR}
LOAD:00004A38 04 F0 9D E4                 LDR             PC, [SP-0xC+arg_C],#4
LOAD:00004A38             ; End of function sub_4A04
LOAD:00004A38
LOAD:00004A3C
LOAD:00004A3C             ; =============== S U B R O U T I N E =======================================
LOAD:00004A3C
LOAD:00004A3C
LOAD:00004A3C             sub_4A3C                                ; CODE XREF: sub_4AE4:loc_4AE8j
LOAD:00004A3C
LOAD:00004A3C             var_8           = -8
LOAD:00004A3C             var_4           = -4
LOAD:00004A3C             arg_8           =  8
LOAD:00004A3C
LOAD:00004A3C 04 70 2D E5                 STR             R7, [SP,#-4]!
LOAD:00004A40 00 70 0F E1                 MRS             R7, CPSR
LOAD:00004A44 04 20 2D E5                 STR             R2, [SP,#-4]!
LOAD:00004A48 01 10 CE E3                 BIC             R1, LR, #1
LOAD:00004A4C 80 01 B1 E7                 LDR             R0, [R1,R0,LSL#3]!
LOAD:00004A50 04 10 91 E5                 LDR             R1, [R1,#4]
LOAD:00004A54 00 00 51 E3                 CMP             R1, #0
LOAD:00004A58 0E 00 00 0A                 BEQ             loc_4A98
LOAD:00004A5C 01 00 11 E3                 TST             R1, #1
LOAD:00004A60 7F 20 A0 13                 MOVNE           R2, #0x7F ; ''
LOAD:00004A64 21 22 02 10                 ANDNE           R2, R2, R1,LSR#4
LOAD:00004A68 02 00 40 10                 SUBNE           R0, R0, R2
LOAD:00004A6C 02 00 11 E3                 TST             R1, #2
LOAD:00004A70 7F 20 A0 13                 MOVNE           R2, #0x7F ; ''
LOAD:00004A74 A1 25 02 10                 ANDNE           R2, R2, R1,LSR#11
LOAD:00004A78 02 00 80 10                 ADDNE           R0, R0, R2
LOAD:00004A7C 04 00 11 E3                 TST             R1, #4
LOAD:00004A80 FF 20 A0 13                 MOVNE           R2, #0xFF
LOAD:00004A84 21 29 02 10                 ANDNE           R2, R2, R1,LSR#18
LOAD:00004A88 02 00 20 10                 EORNE           R0, R0, R2
LOAD:00004A8C 01 2E A0 E1                 MOV             R2, R1,LSL#28
LOAD:00004A90 C2 0F 20 E0                 EOR             R0, R0, R2,ASR#31
LOAD:00004A94 21 0D 80 E0                 ADD             R0, R0, R1,LSR#26
LOAD:00004A98
LOAD:00004A98             loc_4A98                                ; CODE XREF: sub_4A3C+1Cj
LOAD:00004A98 0E 00 80 E0                 ADD             R0, R0, LR
LOAD:00004A9C 04 20 9D E4                 LDR             R2, [SP],#4
LOAD:00004AA0 07 F0 29 E1                 MSR             CPSR_cf, R7
LOAD:00004AA4 04 70 9D E4                 LDR             R7, [SP],#4
LOAD:00004AA8 08 E0 9D E5                 LDR             LR, [SP,#8]
LOAD:00004AAC 08 00 8D E5                 STR             R0, [SP,#8]
LOAD:00004AB0 03 80 BD E8                 LDMFD           SP!, {R0,R1,PC}
LOAD:00004AB0             ; End of function sub_4A3C

----------------------------------------------------------------------------------------------
在拿一個調整表做例子：
LOAD:00009884 01 48                       LDR             R0, =5
LOAD:00009888 FB F7 60 E8                 BLX             dyna_pc
LOAD:0000988C 05 00 00 00 dword_988C      DCD 5            
LOAD:00009890 1C 00 00 00                 DCD 0x1C
LOAD:00009894 40 00 00 00                 DCD 0x40
LOAD:00009898 E4 00 00 00                 DCD 0xE4
LOAD:0000989C 3C 01 00 00                 DCD 0x13C
LOAD:000098A0 88 01 00 00                 DCD 0x188
LOAD:000098A4 08 02 00 00                 DCD 0x208
同上，規律是dyna_pc + 4 (即下一條指令地址[是r0的值] + offset[0 - 5], 因爲表大小為9890 - 98A4 共5個)，
因此證明一共5個跳轉經過這裏，經證明確實如此：
Down j LOAD:000098C4 BL              loc_9888
Down j LOAD:00009966 BL              loc_9888
Down j LOAD:000099BE BL              loc_9888
Down j LOAD:00009A0C BL              loc_9888
Down j LOAD:00009A8A BL              loc_9888
-------------------------------------------------------------------------------------------
sub_494C的特征，代码段中仅存在一处
LOAD:0000B264 ; ---------------------------------------------------------------------------
LOAD:0000B264                 PUSH.W          {R4-R8,LR}
LOAD:0000B268                 ADD             R7, SP, #0xC
LOAD:0000B26A                 PUSH            {R0,R1,LR}
LOAD:0000B26C                 LDR             R0, =0x20
LOAD:0000B26E                 BL              loc_B140   // 又跳回了LOAD:0000B140                 BLX             sub_494C
LOAD:0000B26E ; ---------------------------------------------------------------------------
可以看到并想象程序中有多种类似的跳转，
特征：
PUSH            {R0,R1,LR}  
LDR             R0, =number
NOP
patch代码摘自网络，被放置在put_unconditional_branch.py文件中，
在B26A处执行patch脚本，运行结果如下：B26A处指令变成了B loc_B4B0
LOAD:0000B264             ; ---------------------------------------------------------------------------
LOAD:0000B264 2D E9 F0 41                 PUSH.W          {R4-R8,LR}
LOAD:0000B268 03 AF                       ADD             R7, SP, #0xC
LOAD:0000B26A 21 E1                       B               loc_B4B0
LOAD:0000B26C 01 48                       LDR             R0, =0x20
LOAD:0000B26E FF F7 67 FF                 BL              loc_B140
LOAD:0000B26E             ; ---------------------------------------------------------------------------

LOAD:0000B4B0             ; ---------------------------------------------------------------------------
LOAD:0000B4B0
LOAD:0000B4B0             loc_B4B0
LOAD:0000B4B0 82 B0                       SUB             SP, SP, #8
LOAD:0000B4B2 82 B0                       SUB             SP, SP, #8 // 这段代码包含一个blx跳转，该跳转
LOAD:0000B4B4 03 B5                       PUSH            {R0,R1,LR} //	仅仅是完成了跳到下一个指令的位置
LOAD:0000B4B6 F9 F7 56 EA                 BLX             sub_4964   //	并且计算出指定寄存器的值
LOAD:0000B4BA EA 00                       LSLS            R2, R5, #3 //	这段类似代码都可以被patch掉
LOAD:0000B4BC 00 00                       MOVS            R0, R0 //
LOAD:0000B4BE 02 BC                       POP             {R1} //
LOAD:0000B4C0 00 28                       CMP             R0, #0 //
LOAD:0000B4C2 79 44                       ADD             R1, PC //
LOAD:0000B4C4 09 68                       LDR             R1, [R1] 
LOAD:0000B4C6 03 B5                       PUSH            {R0,R1,LR}
LOAD:0000B4C8 01 48                       LDR             R0, =0x27
LOAD:0000B4CA FF F7 39 FE                 BL              loc_B140
LOAD:0000B4CA             ; ---------------------------------------------------------------------------



sub_4964处指令只是完成了 PC = R1 = B5A4, LR = B4BE(它下一条指令处)， R0, R1略
LOAD:00004964             ; =============== S U B R O U T I N E =======================================
LOAD:00004964
LOAD:00004964
LOAD:00004964             sub_4964                               
LOAD:00004964                                                     
LOAD:00004964
LOAD:00004964             arg_C           =  0xC
LOAD:00004964             arg_10          =  0x10
LOAD:00004964
LOAD:00004964 01 00 CE E3                 BIC             R0, LR, #1  // LR最低位清零，最终R0仍为B4BA
LOAD:00004968 00 10 90 E5                 LDR             R1, [R0] // R1 = [B4BA] = 0XEA
LOAD:0000496C 01 10 90 E7                 LDR             R1, [R0,R1] // R1 = B4BA + 0XEA = B5A4
LOAD:00004970 04 E0 8E E2                 ADD             LR, LR, #4 // B4BA + 4 = B4BE
LOAD:00004974 0C E0 8D E5                 STR             LR, [SP,#0xC]
LOAD:00004978 10 10 8D E5                 STR             R1, [SP,#0x10]
LOAD:0000497C 03 C0 BD E8                 LDMFD           SP!, {R0,R1,LR,PC} // PC = B4BE(它下一条指令处)
LOAD:0000497C             ; End of function sub_4964
LOAD:0000497C
LOAD:00004980             ; ---------------------------------------------------------------------------

特征如下：
SUB SP, SP, #8
PUSH {R0,R1,LR}
....
POP xxx
摘自网络的patch代码见patches.py文件，在B4B2处进行patch后代码变化如下：
LOAD:0000B4B0             ; ---------------------------------------------------------------------------
LOAD:0000B4B0
LOAD:0000B4B0             loc_B4B0
LOAD:0000B4B0 82 B0                       SUB             SP, SP, #8
LOAD:0000B4B2 00 BF                       NOP
LOAD:0000B4B4 01 49                       LDR             R1, =0xB5A4 // = 0x7F73A  
LOAD:0000B4B6 09 68                       LDR             R1, [R1]
LOAD:0000B4B8 02 E0                       B               loc_B4C0
LOAD:0000B4B8             ; ---------------------------------------------------------------------------
LOAD:0000B4BA EA 00       word_B4BA       DCW 0xEA
LOAD:0000B4BC A4 B5 00 00 dword_B4BC      DCD 0xB5A4
LOAD:0000B4C0             ; ---------------------------------------------------------------------------
LOAD:0000B4C0
LOAD:0000B4C0             loc_B4C0                                ; CODE XREF: LOAD:0000B4B8j
LOAD:0000B4C0 00 28                       CMP             R0, #0
LOAD:0000B4C2 79 44                       ADD             R1, PC //  __stack_chk_guard
LOAD:0000B4C4 09 68                       LDR             R1, [R1]
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
另一块类似代码，特征：

LOAD:0007203C 03 B5                       PUSH            {R0,R1,LR}
LOAD:0007203E 00 BF                       NOP
LOAD:00072040 92 F7 AA EC                 BLX             sub_4998
LOAD:00072044 0C 00                       MOVS            R4, R1
-------------------------------------------------------------------------------------------------------------------

LOAD:00004998
LOAD:00004998
LOAD:00004998             sub_4998                              
LOAD:00004998                                                     
LOAD:00004998
LOAD:00004998             arg_8           =  8
LOAD:00004998
LOAD:00004998 01 00 CE E3                 BIC             R0, LR, #1 // 对LR = 0x72044最低位清零，仍为72044
LOAD:0000499C 00 10 90 E5                 LDR             R1, [R0] // 取R1 = [0x72044] = 0xc
LOAD:000049A0 0E 10 81 E0                 ADD             R1, R1, LR // 对LR = 0x72044 + 0xc = 0x72050 
LOAD:000049A4 08 E0 9D E5                 LDR             LR, [SP,#8]
LOAD:000049A8 08 10 8D E5                 STR             R1, [SP,#8]
LOAD:000049AC 03 80 BD E8                 LDMFD           SP!, {R0,R1,PC} // PC = 0x72050 
LOAD:000049AC             ; End of function sub_4998

----------------------------------------------------------------------------------------------------------------
摘自网络命名位put_unconditional_branch1.py文件patch 0x7203C。

LOAD:0007203C                 B               loc_72050
LOAD:0007203E                 NOP
LOAD:00072040                 BLX             sub_4998
LOAD:00072044                 MOVS            R4, R1
LOAD:00072046                 MOVS            R0, R0

---------------------------------------------------------------------------------------------------------------
另一種計算pc的特徵：
LOAD:00009A50 FA F7 A2 EF                 BLX             sub_4998
LOAD:00009A50             ; ---------------------------------------------------------------------------
LOAD:00009A54 7A FF FF FF                 DCD 0xFFFFFF7A
LOAD:00009A58             ; ---------------------------------------------------------------------------

sub_4998
LOAD:00004998             arg_8           =  8
LOAD:00004998
LOAD:00004998 01 00 CE E3                 BIC             R0, LR, #1 // lr = 9A54
LOAD:0000499C 00 10 90 E5                 LDR             R1, [R0] // 0xFFFFFF7A
LOAD:000049A0 0E 10 81 E0                 ADD             R1, R1, LR  // 0x9ace = 9A54 + 0x7a
LOAD:000049A4 08 E0 9D E5                 LDR             LR, [SP,#8]
LOAD:000049A8 08 10 8D E5                 STR             R1, [SP,#8]
LOAD:000049AC 03 80 BD E8                 LDMFD           SP!, {R0,R1,PC} // 0x9ace
以上指令等價於下面僞代碼：
bl (lr + [lr])
---------------------------------------------------------------------------------------------------------------
另一種計算pc的特徵:
LOAD:00009BBC 00 F0 0C B8                 B.W             loc_9BD8
LOAD:00009BC0             ; ---------------------------------------------------------------------------


LOAD:00009BD8             loc_9BD8    
LOAD:00009BD8                              
LOAD:00009BD8 71 46                       MOV             R1, LR // lr = 9BC0 
LOAD:00009BDA 02 A5                       ADR             R5, 0x9BE4
LOAD:00009BDC 55 F8 21 10                 LDR.W           R1, [R5,R1,LSL#2] ; 30ae4 = 0xFE6B
LOAD:00009BE0 29 44                       ADD             R1, R5  ; 19A4F
LOAD:00009BE2 08 47                       BX              R1 // 動態跳轉
LOAD:00009BE2             ; ---------------------------------------------------------------------------
LOAD:00009BE4 DD FF FF FF                 DCD 0xFFFFFFDD
LOAD:00009BE8             ; ---------------------------------------------------------------------------

---------------------------------------------------------------------------------------------------------------
另一種計算pc的特徵（同時動態計算寄存器值，參數動態生成）：
LOAD:00004D12 82 B0                       SUB             SP, SP, #8
LOAD:00004D14 03 B5                       PUSH            {R0,R1,LR}
LOAD:00004D16 FF F7 26 EE                 BLX             sub_4964 
LOAD:00004D16             ; ---------------------------------------------------------------------------
LOAD:00004D1A EE 31 00 00                 DCD 0x31EE
LOAD:00004D1E             ; ---------------------------------------------------------------------------
LOAD:00004D1E 01 BC                       POP             {R0} // pop xxx，動態生成參數

sub_4964 
LOAD:00004964 01 00 CE E3                 BIC             R0, LR, #1 // 4D1A
LOAD:00004968 00 10 90 E5                 LDR             R1, [R0] // 0x31EE
LOAD:0000496C 01 10 90 E7                 LDR             R1, [R0,R1] // r1 = [4D1A + 0x31EE] = [7f08] = 0x85ECC
LOAD:00004970 04 E0 8E E2                 ADD             LR, LR, #4 // lr = 4D1E
LOAD:00004974 0C E0 8D E5                 STR             LR, [SP,#0xC] // lr + 4 ,下一條指令処
LOAD:00004978 10 10 8D E5                 STR             R1, [SP,#0x10] // 待彈出寄存器值0x85ECC
LOAD:0000497C 03 C0 BD E8                 LDMFD           SP!, {R0,R1,LR,PC} // pc = pc + 8
等同於僞代碼：
arg_addr = [lr + [lr]]
r{0-3} = arg_addr
---------------------------------------------------------------------------------------------------------------
程序JNI_OnLoad邏輯：
libsgmainso_6.4.36.so B3F2D000 B3FB6000 R . X D . byte 00 public CODE 32 00 00
sp = BE903640  B1200284  debug038:B1200284
第一個動態pc：
libsgmainso_6.4.36.so:B3F38140 BLX             dyna_pc
動態arg：
libsgmainso_6.4.36.so:B3F384B6 BLX             dyna_arg
libsgmainso_6.4.36.so:AFE80210 BL              loc_AFEF14F4(重命名為goto_create_global_objs)
sub_7C4F4();   // 創建全局 jboolean， jinteger、jstring

调试时跳过这里，否则可能崩溃
LOAD:0000B584 71 F0 14 F8                 BL              goto_getenv(7C5B0)
---------------------------------------------------------------------------------------------------------------
#sub_72CCC()，被重命名為goto_do_httpuitl
主要完成對com/taobao/wireless/security/adapter/common/HttpUtil的各種方法的查找
獲取對應的MethodId並保存

sub77dbc(), 代码複合patch代码第二種特征，但是这里应该不被patch，被patch的地方
82 B0       SUB             SP, SP, #8
03 B5       PUSH            {R0,R1,LR}
91 F7 CC ED BLX             dyna_arg
32 01       LSLS            R2, R6, #4
00 00       MOVS            R0, R0
01 BC       POP             {R0}
应该满足两个SUB             SP, SP, #8指令，因此運行patch代碼，patch整個代碼段
會出錯，它會把{R0,R1,LR}指令patch成b xxxx導致運行失敗。
sp = BE903620  AFE80111  libsgmainso_6.4.36.so:AFE80111
BL              sub_B3FA0E24(sub_73e24()，被重命名為goto_decrypt_entry)
arg:B3FB2FA9, BE9035C3,0x35 // 參數1為加密數據緩存區，參數2是解密數據緩存區
sub_B3FA0E56(sub_73e56, 被重命名為decrypt_entry),比較重要的函數涉及創建容器結構體和解密
BL unk_B3FA7F78(goto_create_vdata)
BL sub_B3FA7FB6(create_vdata)
arg:vdata1,"DcO/lcK+h?m3c*q@",0x10
//vdata1->make_vdata 填充數據
libsgmainso_6.4.36.so:B3FA0E94 98 47 BLX     R3(7AA5D‬)
拷貝"DcO/lcK+h?m3c*vaq@"到vdata1的data1中

第二次調用make_vdata，arg:vdata2,B3FB2FA9,52 // 參數2是數據緩存區
這次是把下面這52個字節拷貝到vdata2的data2中
0xF9,0xA7,0x21,0x3D,0x8C,0x3E,0xFE,0x77,0x18,0x40,0xDB,0x2A,
0xAD,0x4A,0xC5,0xF9,0xA1,0x56,0x75,0x54,0x23,0xBE,0xC7,0xA6, 
0x7A,0x35,0xEC,0x8E,0xB2,5,0x74,0x11,0x93,0x58,0x7F,0x6E,0x3A,
0xE3,0x4F,0x9D,0x54,3,0x7E,0x6B,0xFA,0x1B,0x5B,0xE3,0xF8,0xC1,2,0xF9 
dcryptdata:BE903578
memset(BE903578, 0, 20)
arg:BE903578,BE903594,20,20
// 進入解密函數，dcryptdata結構對應内存
[stack]:BE903578 DCD 0
[stack]:BE90357C DCD 3 ; caseno
[stack]:BE903580 DCD 0
[stack]:BE903584 DCD 0
[stack]:BE903588 DCD 0xACC1C890 ; vdata1
[stack]:BE90358C DCD 0xACC1C8C8 ; vdata2
libsgmainso_6.4.36.so:B3FA0ED8 BL       sub_B3F8E15C(重命名為goto_dcrypto)
goto_dcrypto(dcryptdata, )
進入sub_611b4(被重命名為decrypto)進行解密，解密出：
"com/taobao/wireless/security/adapter/common/HttpUtil"
libsgmainso_6.4.36.so AFE75000 AFEFE000 R . X D . byte 00 public CODE 32 00 00
調用findclass查找該class，調用NewGlobalRef創建該類的ref
arg: httputilref, 
bl sub_72d60()
// 參數1加密數據，參數2為解密緩衝區，參數3為長度
BL              goto_decrypt_entry(encdata, decdata, len);
BL              goto_create_vdata
memset (BE9035A0, 0, 0x1d)
拷貝加密數據到vdata2
memset dcryptdata 結構BE903558
BL              goto_dcrypto, 解密出字符串"sendSyncHttpGetRequestBridge" 
調用env->getStaticMethodID,75F247D8
sub_72e54()
解密出數據"sendSyncHttpPostRequestBridge"
調用env->getStaticMethodID, 75F24828
在解密出"downloadFileBridge" 
調用env->getStaticMethodID, 75F24788
調用env->DeleteLocalRef刪除httputilref
至此sub_72CCC()結束
---------------------------------------------------------------------------------------------------------------
sub_73634()被重命名為goto_do_umidAdapter
主要完成對com/taobao/wireless/security/adapter/umid/UmidAdapter的方法的查找
並保存其MethodId
sub_7366A‬()
BL    goto_decrypt_entry(,, 54)
解密出"com/taobao/wireless/security/adapter/umid/UmidAdapter"
調用env->findclass找到UmidAdapterClass 00100025,調用env->NewGlobalRef UmidAdapterRef
調用env->DeleteLocalRef, 刪除UmidAdapterClass
BL    goto_decrypt_entry(AFEFB113, BE9035B8, 16)
解密出"umidInitAdapter"
調用env->getStaticMethodID(UmidAdapterRef, "umidInitAdapter") 75F248C8
sub_73634()結束
---------------------------------------------------------------------------------------------------------------
sub_73E24()      goto_decrypt_entry(AFEF8EA6, BE9035E8, 49)
解密出"com/taobao/wireless/security/adapter/JNICLibrary"
libsgmainso_6.4.36.so B3F2D000 B3FB7000 R . X D . byte 00 public CODE 32 00 00
調用env->findclass查找JNICLibrary 00200025
bl 9EE4‬
sub_9ee4() 被重命名為goto_create_command_vdata，主要是調用sub_9F1C完成創建兩個大的結構體
sub_9F1C() // make_global_command_ptr
首先讀取off_90804処的值是否為NULL(被重命名為global_command_entryptr
它保存著下面的global_command_entry結構的指針)

struct global_command_entry { // 記錄著生成和執行command的核心方法
	void* goto_make_command_entry; // 對應sub_9B3C; 生成command結構核心算法
	void* goto_do_command1; // // 對應sub_9d82; command_native_inner
	void* goto_do_command2; // 對應sub_9e7e; 和sub_9d82差不多
};

ACC11F60 = malloc(12); // 這是個什麽結構體,暫且命名為tmp_vdata
debug014:ACC11F60 DCD 0xB3F36A99 // 對應sub_9B3C; 生成command結構核心算法
debug014:ACC11F64 DCD 0xB3F36DF5 // 對應sub_9d82; command_native_inner
debug014:ACC11F68 DCD 0xB3F36E49 // 對應sub_9e7e; 和sub_9d82差不多
sub_7B86C(32,0) // 重命名為create_command_vdata(int len, int w); // len表示結構體大小，w未知
struct command_nest {
	void* nf1;
	void* nf2;
	int len;
};

struct command_vdata {
	struct data** datalist; // 第一層$8bitstruct
	int data_count;
	int data_size;
	void* f1;
	void* f2;
	void* f3;
	struct command_nest* nest;
};

ACC3A3D0 = malloc(36);
創建command_vdata結構體，對應内存結構：
debug014:ACC3A3D0 DCD 0xACC49300                          ; command_vdata1
debug014:ACC3A3D4 DCD 0
debug014:ACC3A3D8 DCD 0x20
debug014:ACC3A3DC DCD 0xB3FA88F9
debug014:ACC3A3E0 DCD 0xB3FA89B5
debug014:ACC3A3E4 DCD 0xB3FA89F5
debug014:ACC3A3E8 DCD 0xB3FA8A81
debug014:ACC3A3EC DCD 0xB3FA8AF1
debug014:ACC3A3F0 DCD 0
創建data結構體(chunk)
ACC49300 = malloc(128);
創建第二個command_vdata結構體ACC3A3A8
debug014:ACC3A3A8 DCD 0xACC49280                          ; command_vdata2
debug014:ACC3A3AC DCD 0
debug014:ACC3A3B0 DCD 0x20
debug014:ACC3A3B4 DCD 0xB3FA88F9
debug014:ACC3A3B8 DCD 0xB3FA89B5
debug014:ACC3A3BC DCD 0xB3FA89F5
debug014:ACC3A3C0 DCD 0xB3FA8A81
debug014:ACC3A3C4 DCD 0xB3FA8AF1
debug014:ACC3A3C8 DCD 0
創建第二個data結構體ACC49280
然後把它倆存儲在以下地方：
off_8CA7C g_search_command_vdata DCD 0xACC3A3D0, do_command 第四個參數為0，查找
off_8CA78 gcommand_build_vdata DCD 0xACC3A3A8, do_command 第四個參數為1，生成
在off_90804処保存global_command_entry指針
---------------------------------------------------------------------------------------------------------------
bl sub_71D68()‬,重命名為goto_do_SPUtility2
主要是查找com/taobao/wireless/security/adapter/common/SPUtility2的一些methoidID
sub_73DD4()啥也沒乾

sub_71E70只是用來構造參數
sub_72080()
解密得到"com/taobao/wireless/security/adapter/common/SPUtility2"
調用env->findclass找到SPUtility2Class 00000029
調用env->NewGlobalRef創建SPUtility2Ref 001003DA
sub_72134()
解密"readFromSPUnified"
調用env-getStaticMethodID, 75F26B48
解密"saveToFileUnifiedForNative"
調用env-getStaticMethodID, 75F26C88
sub_720C8‬()
解密出 "removeFromSPUnifiedp"
調用env-getStaticMethodID, 75F26BE8
sub_71FD0‬()
解密出"readSS"
解密出"writeSS"，調用env-getStaticMethodID, 75F26D78
sub_71EB0()
調用env-getStaticMethodID("readSS"), 75F26B98
解密出"read"， "write"
調用env-getStaticMethodID("read"),75F26AF8
調用env-getStaticMethodID("write"),75F26D28
---------------------------------------------------------------------------------------------------------------
sub_e7dc()
sub_E890‬()
解密出"(I)Ljava/lang/String;"
解密出"com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer"
調用findclass，0010002D，調用NewGlobalRef創建該類的ref 001003DE
調用DeleteLocalRef, 刪除本地DeviceInfoCapturer類的ref
解密出"doCommandForString"
調用env-getStaticMethodID("doCommandForString"),75F27048  存儲在off_8CA94処
存儲在以下位置：
off_8CA94 global_DeviceInfoCapturer_methodId DCD 0x75F27048
off_8CA98 global_DeviceInfoCapturer_ref DCD 0xB6F33E04

#########################################################################################
#sub_9B3C
‬這是一個重要的函數，每個command依賴的數據結構都需要經過它來生成
這個函數經過了llvm混淆，在不去掉llvm混淆時分析起來還是比較費勁的。
command 最主要的參數是三個：
command / 10000 ; // n1
command % 10000 / 100 ; // n2
command % 100 ; // n2
由此三個參數構成了三層結構(由外向内順序是n1->n2->n3)，其中最終的加密后的地址保存在
n3層結構中（只是異或加密），解密密匙保存在n2層結構中（是用time做種子生成的隨機數，
每次都不一樣，每個app可能都不一樣）。

每個command相關地址并不是函數的實際地址（是包含實際地址的封裝），是執行函數的一個入口（梉），
這個入口需要進一步做處理才能跳轉到實際函數的地址。
一個函數會被分成不同的塊，由n3層結構決定，例如：
command(1, 17, 1) { // 隨便假設的
	stub2->do_command_parser->real_func_addr
	stub1->do_command_parser->real_func_addr
	stub3->do_command_parser->real_func_addr
	stub4->do_command_parser->real_func_addr
}
在上面的分析中我們已經看到它生成了一個全局的command_entryptr，它記錄著生產command相關結構
和反向按結構找到梉的算法。
同時還生成了兩個gcommand_vdata1和gcommand_vdata2的n1第一層指針結構（分別為查找和生成時使用）

主要結構如下（僞定義）：

n1 -> first struct{8 bit: n2_addr, count} -> n2 -> second {24 bit: n3_addr, count} -> n3 ->
third {16 bit: stub_addr, count}

無論是正向生成command相關結構，還是反向依賴參數查找結構都需要這三個參數
1、正向生成command相關結構，傳遞的參數是1
2、反向查找command相關結構，傳遞的參數是0

#後續在酌情添加
開始分析：
sub_9B3C‬() // goto_make_command_entry
以第一次分析爲例（我只記錄關鍵邏輯）：
[stack]:BE8915C8 DCD 0xB3E7B2B5 ; sp
[stack]:BE8915CC DCD 0x100025
sub_9B3C‬(1, 9, 1, 1, build_addr) -> 
// goto_build_or_unpack_command
sub_9854(gcommand_build_vdata, 1, 9, 1, 1, ...) ->

sub_9a14(gcommand_build_vdata, 1, 9, 1, 1, build_addr = 0xB3E7B2B5) // build_addr = 0x102B5

struct $8bitstruct { // 第一層結構
	int command_arg1; // command arg1
	struct command_vdata* vdata; // 指向第二層
};

struct $24bitstruct { // 第二層結構
	int command_arg1; // command arg1
	int command_arg2; // command arg2
	long time;
	int c; // (time >> 31)
	struct command_vdata* vdata; // 指向第三層
	int d; // 未知
};

struct $16bitstruct { // 第三層結構
	int command_arg1; // command arg1
	int command_arg2; // command arg2
	int command_arg3; // command arg3
	int xoraddr;
};

// w = 0代表查找， w = 1代表創建
// n1, n2, n3 為command 三層索引
// build_addr 正向時為被處理地址， 反向時為返回地址
void* sub_9a14(command_vdata* g_build_vdata, int n1, int n2, int n3, w = 1, void* build_addr) {
	
	int data_count = g_build_vdata->data_count;
	int i = 0;
	if (data_count < 1) {
		if (w == 0) {
			return 0x26b0;
		}
		
		struct $8bitstruct* _8bitstruct = (struct $8bitstruct*) malloc(8); // B4E01130
		memset(_8bitstruct, 0, 8);
		_8bitstruct->command_arg1 = n1;
		// -> 7BB98
		
		// vdata = ACB4A3F8, datalist = ACB32980
		// vdata 初始化略; 默認data_size為120字節
		struct command_vdata* second_command_vdata = (struct command_vdata*) malloc(36); 
		
		_8bitstruct->vdata = second_command_vdata;
		// make_command_vdata， 填充數據
		// 這裏僅僅執行了 vdata->datalist->d = _8bitstruct;
		// vdata->data_count++;
		g_build_vdata->f2(g_build_vdata, 0, _8bitstruct); 
		
		if(second_command_vdata->data_count < 1) {
			if (w == NULL) {
				return 0x26B1;
			}
			// ACB12478
			struct $24bitstruct* _24bitstr = (struct $24bitstruct*) malloc(24);
			memset(_24bitstr, 0, 24);
			_24bitstr->command_arg1 = n1; // command arg1
			_24bitstr->command_arg2 = n2; // command arg2
			time_t seed;
			seed = time(NULL); // 5E58B699
			srand(seed);
			int random_time = (int) rand() >> 31; // 074D4C00
			int c = (int) random_time >> 31; // 0
			_24bitstr->time = random_time;
			_24bitstr->c = c;
			// 創建第三層command_vdata結構
			// vdata = ACB4A498; data = ACB32A00
			// vdata 初始化略
			struct command_vdata* third_command_vdata = (struct command_vdata*) malloc(36); 
			_24bitstr->vdata = third_command_vdata;
			// 這裏僅僅執行了 vdata->datalist->d = _24bitstr;
			// vdata->data_count++;
			second_command_vdata->f2(second_command_vdata, _24bitstr); // make_command_vdata
			if (third_command_vdata->data_count < 1) {
				if (w == 0) {
					return 0x270F;
				}
				// ACB3B540
				struct $16bitstruct* _16bitstr = (struct $16bitstruct*) malloc(16);
				_16bitstr->command_arg1 = n1;
				_16bitstr->command_arg2 = n2;
				_16bitstr->command_arg3 = n3;
				// make_command_vdata， 填充數據
				// 這裏僅僅執行了 vdata->datalist->d = _16bitstr;
				// vdata->data_count++;
				third_command_vdata->f2(third_command_vdata, _16bitstr);// make_command_vdata
				// 異或加密地址存儲
				_16bitstr->xoraddr = _24bitstr->time ^ build_addr;
				return 0;
				
			} else {
				i  = 0;
				while (i < third_command_vdata->data_count) {
					// 這裏後面在說
				}
			}
		} else {
			i = 0;
			while(i < second_command_vdata->data_count) {
				// 這裏後面在說
			}
			
		}
	} else {
		struct data** datalist = g_build_vdata->datalist;
		struct $8bitstruct* _8bitstr = NULL;
		for (int i = 0 ; i < g_build_vdata->data_count; i++) {
			_8bitstr = datalist[i];
			if(_8bitstr->command_arg1 == n1) {
				break;
			}
		}
		// 取第二層機構
		struct command_vdata* second_command_vdata = _8bitstr->vdata;
		if (second_command_vdata->data_count < 1 ) {
			return 0x26B1;
		}
		
		datalist = second_command_vdata->datalist;
		struct $24bitstruct* _24bitstr = NULL;
		
		for (int j = 0 ; j < second_command_vdata->data_count ; j++) {
			if((struct $24bitstruct*) datalist[i]->command_arg2 == n2) {
				_24bitstr = datalist[i];
				break;
			}
		}
		
		if (w == 0) {
			return ??;
		}
		
		if (_24bitstr == NULL) {
			_24bitstr = malloc(24);
			// 創建$24bitstruct 結構體
			// 創建third_command_vdata ACB4A4C0;同上
			// 更新second_command_vdata datalist同時data_count++等
			// ACB124C0  24bitstr, 
			// 創建完后調用
		}
		
		// 取第三層
		struct $16bitstruct* _16bitstr = NULL;
		struct command_vdata* third_command_vdata = _24bitstr->vdata;
		if(third_command_vdata->data_count < 1) {
			
		}
		
		for (j = 0; j < third_command_vdata->data_count; j++) {
			if ((struct $16bitstruct*) third_command_vdata[j]->command_arg3 == n3) {
				_16bitstr = third_command_vdata[j];
				break;
			}
		}
		
		if (w == 0) {
			return ??;
		}
		
		if (_16bitstr == NULL) {
			_16bitstr = malloc(16);
			// ACB11F50
			// 創建$16bitstruct; 同上
			return 0;
		}
	}
}

#########################################################################################
---------------------------------------------------------------------------------------------------------------
sub_69D68‬() 啥也沒乾
---------------------------------------------------------------------------------------------------------------
sub_197B4() 被重命名為goto_do_DataReportJniBridgerer
主要是處理com/taobao/wireless/security/adapter/datareport/DataReportJniBridgerer這個類的方法，同上
sub_1990C‬()
解密出"com/taobao/wireless/security/adapter/datareport/DataReportJniBridgerer"
調用findclass， 0000002D
調用NewGlobalRef創建該類的ref 001003E2
sub_19998‬()
下面忘記下斷點了，丟失信息了
解密出"sendReportBridge", 調用getStaticMethodID, 忘記記錄了
解密出 "accsAvaiableBridge", 調用getStaticMethodID, 忘記記錄了
解密出"()I" , 調用getStaticMethodID, 忘記記錄了
解密出"registerAccsListnerBridge"
解密出"()I" , 調用getStaticMethodID, 忘記記錄了
他們被分別保存在off_8CB80起始的地址処
sub_73D90()‬ 讀取global_command_entry指針的值
繼續調用sub_9b3c(1, 0xb, 0x34, 1, build_addr = B3E84725 = 0x19725) 詳細分析見上面
---------------------------------------------------------------------------------------------------------------
sub_E240‬()
sub_e280()
又sub_9B3C‬(1, 7, 1, 1, build_addr = 0xB3E791D5 = off_E1D5)同上, 不在繼續分析
---------------------------------------------------------------------------------------------------------------
sub_B8B0()‬
繼續調用sub_9B3C‬(1, 1, 1, 1, build_addr = 0xB3E76921 = off_B921) 同上略
繼續調用sub_9B3C‬(1, 1, 2, 1, build_addr = 0xB3E76FD9 = off_BFD9) 同上略
---------------------------------------------------------------------------------------------------------------
sub_5F0F4‬()
sub_5F11E‬()
sub_9B3C‬() 同上略
---------------------------------------------------------------------------------------------------------------
sub_5F0F4(env, clazz)
sub_9B3C‬() 同上略
sub_9B3C‬() 同上略
---------------------------------------------------------------------------------------------------------------
sub_70640(env, clazz)
sub_9B3C‬() 同上略
sub_9B3C‬() 同上略
---------------------------------------------------------------------------------------------------------------
sub_11F3C(env)  
sub_14FEE‬()
sub_1511C()‬，中間很多調用findclass和調用都略
解密出"android/content/Context"，調用findclass
sub_151A4‬()
解密出"getPackageManager","()Landroid/content/pm/PackageManager;"
調用getStaticMethodID 70FC7458
解密出"getContentResolver",  "()Landroid/content/ContentResolver;"
調用getStaticMethodID 70FC7458
解密出"getSystemService"，"(Ljava/lang/String;)Ljava/lang/Object;"
調用getStaticMethodID 70FC7BA8
解密出"WIFI_SERVICE"，"Ljava/lang/String;"
調用GetStaticFieldID 70FC66E8
調用NewGlobalRef創建該類的ref 001003E6
調用DeleteLocalRef刪除該類本地ref
解密出"android/content/pm/PackageManager", "getPackageInfo",，調用findclass
"(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"
調用getStaticMethodID 70FAFA30
調用DeleteLocalRef刪除該類本地ref
解密出"android/content/pm/PackageInfo"
"applicationInfo", "Landroid/content/pm/ApplicationInfo;"
調用GetFieldID 71052F08
解密出 "firstInstallTime1"，"J"
調用GetFieldID 71053100
解密出"lastUpdateTime"，"J"
調用GetFieldID 71053118
調用DeleteLocalRef刪除該類本地ref
解密出"android/content/pm/ApplicationInfo","flags","I"
調用GetFieldID 71047168
調用DeleteLocalRef刪除該類本地ref
解密出"android/provider/Settings"， "getString"
"(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;"
調用getStaticMethodID 7127C4E8
調用NewGlobalRef創建該類的ref 001003EA
調用DeleteLocalRef刪除該類本地ref
"java/util/List","get", "(I)Ljava/lang/Object;",
調用getStaticMethodID 70B43A50
解密出"size","()I"
調用getStaticMethodID 70B43DF8
調用DeleteLocalRef刪除該類本地ref
解密出"android/net/wifi/WifiConfiguration"，"SSID"，"Ljava/lang/String;"
調用GetFieldID 75F27C38
"networkId","I",調用GetFieldID 75F28078
"providerFriendlyName","Ljava/lang/String;",調用GetFieldID, 返回空
"BSSID"，"Ljava/lang/String;",調用GetFieldID, 75F27BF8
"FQDN","Ljava/lang/String;",調用GetFieldID, 75F27C18
"priority","I", 調用GetFieldID,75F282B8
"hiddenSSID"，"Z"，調用GetFieldID, 75F27ED8
調用NewGlobalRef創建該類的ref 001003EE
調用DeleteLocalRef刪除該類本地ref
"android/net/wifi/WifiManager"，"getConfiguredNetworks"，"()Ljava/util/List;"
調用getStaticMethodID 711FD720
"getDhcpInfo","()Landroid/net/DhcpInfo;"，
調用getStaticMethodID 711FD840
調用DeleteLocalRef刪除該類本地ref
"android/net/DhcpInfo"， "gateway"，"I",
調用GetFieldID 75F29168
調用DeleteLocalRef刪除該類本地ref
---------------------------------------------------------------------------------------------------------------
sub_21C3C()
sub_21c70()
sub_9b3c() 同上略
...
---------------------------------------------------------------------------------------------------------------
sub_2148C()
sub_9b3c() 同上略
...
---------------------------------------------------------------------------------------------------------------
sub_210E0
sub_9b3c() 同上略
...
---------------------------------------------------------------------------------------------------------------
sub_41B58
sub_9b3c() 同上略
...
---------------------------------------------------------------------------------------------------------------
sub_27920
sub_9b3c() 同上略
...
---------------------------------------------------------------------------------------------------------------
sub_293E8()
sub_2941C()->sub_29708()->sub_29918‬()
解密出"com/taobao/dp/util/ZipUtils"，"unZip"，"([B)[B"
findclass找到ZipUtilsClass 00100031
NewGlobalRef 001003F2
DeleteLocalRef
getMethodID 75F29618
解密出"com/taobao/dp/util/CallbackHelper"
findclass找到CallbackHelper 00000031
NewGlobalRef 001003F6
DeleteLocalRef
getMethodID 75F29618
sub_2abf9()-->sub_2AC24‬()加綫程鎖
DeleteLocalRef
sub_29754()->sub_29BB4‬()
解密出"getPackageManager"， "()Landroid/content/pm/PackageManager;"
"android/content/Context","android/content/pm/PackageManager"
"getPackageInfo","(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"
"android/content/pm/PackageInfo","applicationInfo"
"Landroid/content/pm/ApplicationInfo;","firstInstallTime","lastUpdateTime"
"android/content/pm/ApplicationInfo","flags"
FindClass("android/content/Context") 00100031
NewGlobalRef 001003FA
getMethodID("getPackageManager") 70FC7968
FindClass("android/content/pm/PackageManager") 00000035
NewGlobalRef 001003FE
getMethodID("getPackageInfo") 70FAFA30
FindClass("android/content/pm/PackageInfo") 00000039 ??
NewGlobalRef 00100402
GetFieldID("applicationInfo") 71052F08
GetFieldID("firstInstallTime") 71053100
GetFieldID("lastUpdateTime") 71053118
FindClass("android/content/pm/ApplicationInfo") 0000003D
NewGlobalRef 00100406
GetFieldID("flags") 71047168
---------------------------------------------------------------------------------------------------------------
sub_208F4
sub_20A0C‬()
解密出"com/alibaba/wireless/security/framework/utils/UserTrackMethodJniBridge"
NewGlobalRef 0010040A， DeleteLocalRef
"utAvaiable"，"()I;"，getStaticMethodID("utAvaiable") 75F28278
"addUtRecord"，"(Ljava/lang/String;IILjava/lang/String;JLjava/lang/String;"
"Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I"
sprintf(, "%s%s", "(Ljava/lang/String;IILjava/lang/String;JLjava/lang/String;", 
"Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I")
得到"(Ljava/lang/String;IILjava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;"
"Ljava/lang/String;Ljava/lang/String;)I"
getStaticMethodID("addUtRecord") 75F28188
"getStackTrace","(II)Ljava/lang/String;",getStaticMethodID("getStackTrace"), 75F281D8
判斷獲取的methodId是否為空
---------------------------------------------------------------------------------------------------------------
sub_B7B0
sub_b7f6() 被重命名為registerNatives
解密出"doCommandNative"，"(I[Ljava/lang/Object;)Ljava/lang/Object;", fnPtr為sub_B69C()‬
實際對應sub_B6F6()，重命名為doCommandNative，代碼摘自網絡
sub_9D60為goto_docommand_native_inner
調用env->RegisterNatives()注冊這個doCommandNative
至此JNI_OnLoad結束
---------------------------------------------------------------------------------------------------------------
doCommandNative(12302, new Object[]{1, true}) 對應getSecToken
struct command_arg {
	int arg1;
	int arg2;
	int arg3;
	JNIEnv* env;
	void* args;
};

struct command_arg* = malloc(20); // ACB6A718

int _R4 = 12302; // command
int _R0 = 0x68DB8BAD; // 68DB8BAD
int _R2 = 0x51EB851F; // 51EB851F

int r0 = _R0 * _R4; // 000013AE
int r3 = _R2 * _R4; // 00000F60
// (signed int)r0 >> 0xc) = (signed int) (13AE >> 0xc) = 00000001
// r0 >> 31 = 0
r0 = ((signed int)r0 >> 0xc) + (r0 >> 31); // 0x1, 參數1
int r1 = _R4 - r0 * 10000 ; // 000008FE(2302)
r1 = _R4 * r1; // 2E0, SMMUL.W取高位
// ((signed int)r3 >> 5) = 0000007B(123)
// (r3 >> 31) = 0
r2 = _R4 - (((signed int)r3 >> 5) + (r3 >> 31)) * 100; // 2, 參數3
r3 = (signed) r1 >> 5 = 00000017(23)
r1 = r3 + (r1 >> 31) = 1; // 0x17， 參數2

command_arg->arg1 = 1;
command_arg->arg2 = 0x17;
command_arg->arg3 = 2;
// [stack]:BE892160 DCD 0xACB6A748 sp command_arg
// [stack]:BE892164 DCD 0xBE89216C sp + 4, 棧指針
// [stack]:BE89216C DCD 0
sub_9D60->sub_9D82(1, 0x17, 2, w=1, command_arg, 一個棧變量指針)


// 非0時取這個
libsgmainso_6.4.36.so:B3EF7A78 dword_B3EF7A78 DCD 0xACB4A3D0 
// 0時取這個
libsgmainso_6.4.36.so:B3EF7A7C dword_B3EF7A7C DCD 0xACB4A3A8
/////////////////////////////////////////////////////////////////
// 第一次w = 1 因此這個command_vdata沒有用到
debug021:ACB4A3A8 DCD 0xACB31C00
debug021:ACB4A3AC DCD 0
debug021:ACB4A3B0 DCD 0x20
debug021:ACB4A3B4 DCD 0xB3EE68F9
debug021:ACB4A3B8 DCD 0xB3EE69B5
debug021:ACB4A3BC DCD 0xB3EE69F5
debug021:ACB4A3C0 DCD 0xB3EE6A81
debug021:ACB4A3C4 DCD 0xB3EE6AF1
debug021:ACB4A3C8 DCD 0
//////////////////////////////////////////////////////////////////
// 用到了這個command_vdata
debug021:ACB4A3D0 DCD 0xACB31C80
debug021:ACB4A3D4 DCD 1
debug021:ACB4A3D8 DCD 0x20
debug021:ACB4A3DC DCD 0xB3EE68F9
debug021:ACB4A3E0 DCD 0xB3EE69B5
debug021:ACB4A3E4 DCD 0xB3EE69F5
debug021:ACB4A3E8 DCD 0xB3EE6A81
debug021:ACB4A3EC DCD 0xB3EE6AF1
debug021:ACB4A3F0 DCD 0
// data
debug021:ACB31C80 DCD 0xB4E01130
//
debug068:B4E01130 DCD 1
debug068:B4E01134 DCD 0xACB4A3F8
// command_vdata1
debug021:ACB4A3F8 DCD 0xACB31D00
debug021:ACB4A3FC DCD 0xC
debug021:ACB4A400 DCD 0x20
debug021:ACB4A404 DCD 0xB3EE68F9
debug021:ACB4A408 DCD 0xB3EE69B5
debug021:ACB4A40C DCD 0xB3EE69F5
debug021:ACB4A410 DCD 0xB3EE6A81
debug021:ACB4A414 DCD 0xB3EE6AF1
// 12個data
debug021:ACB31D00 DCD 0xACB125F8
debug021:ACB31D04 DCD 0xACB12610
debug021:ACB31D08 DCD 0xACB125E0
debug021:ACB31D0C DCD 0xACB124C0
debug021:ACB31D10 DCD 0xACB12490
debug021:ACB31D14 DCD 0xACB124F0
debug021:ACB31D18 DCD 0xACB12A00
debug021:ACB31D1C DCD 0xACB12778
debug021:ACB31D20 DCD 0xACB12910
debug021:ACB31D24 DCD 0xACB12AC0
debug021:ACB31D28 DCD 0xACB12970
debug021:ACB31D2C DCD 0xACB12BE0
// 最後取到的符合要求的 對應參數2的結構
debug021:ACB12BE0 DCD 1
debug021:ACB12BE4 DCD 0x17
debug021:ACB12BE8 DCD 0x7A005EB3
debug021:ACB12BEC DCD 0
debug021:ACB12BF0 DCD 0xACB4A7B8
debug021:ACB12BF4 DCD 0
debug021:ACB12BF8 DCD 0
debug021:ACB12BFC DCD 0
debug021:ACB12C00 DCD 0xACB12BC8
//最後取到的符合要求的 對應參數3的結構
debug021:ACB3B340 DCD 1
debug021:ACB3B344 DCD 0x17
debug021:ACB3B348 DCD 2
debug021:ACB3B34C DCD 0xC9E91B96
debug021:ACB3B350 DCD 1
debug021:ACB3B354 DCD 0x17
debug021:ACB3B358 DCD 1
debug021:ACB3B35C DCD 0xC9E91A22
debug021:ACB3B360 DCD 1
debug021:ACB3B364 DCD 0x17
debug021:ACB3B368 DCD 3
debug021:ACB3B36C DCD 0xC9E91B66
debug021:ACB3B370 DCD 1
debug021:ACB3B374 DCD 0x17
debug021:ACB3B378 DCD 4
debug021:ACB3B37C DCD 0xC9E9182E
/////////////////////////////////////////////////////////////

stack
BE892140  00000000
BE892144  BE892148  [stack]:BE892148
BE892148  00000000 //r7 + 1c，後面用來存儲下一跳的地址
BE89214C  B47A9038  dalvik_allocspace_allo
BE892150  0000300E
BE892154  00000000
BE892158  BE892180  [stack]:BE892180
BE89215C  B3E76771  libsgmainso_6.4.36.so:
BE892160  ACB6A718  debug021:ACB6A718

我們設command變量從外到内依次為a、b、c
command_vdata-> {datalistaddr, data_count, ...} 
datalist[0]->data[0]-> data{count, addr}->
command_vdata -> {datalistaddr, data_count, ...}->datalist[x]
->24bitstruct{a, b, time(xorkey), ?, command_vdata,?}->
command_vdata -> {datalistaddr, data_count, ...}->
16bitstruct{a, b, c, xoraddr}

// goto_build_or_unpack_command
sub_9854(ACB4A3D0, 1, 0x17, 2, ...) 
// goto_build_or_unpack_command
sub_9854->sub_9A14‬(a, b, c, ...) // a = arg1, b = arg2, c =arg3
//////////////////////////////////////////////////////////////
// 第一次 sub_9D82(1, 0x17, 2, 1, command_arg, 一個棧變量指針)
//////////////////////////////////////////////////////////////
->sub_9d82(command, tmp2, tmp3, w, ...) // command_native_inner；獲取下一步跳轉地址

// 首先找到全局command_vdata最外層指針，相對文件偏移dword_8CA7C和dword_8CA78
// 前面做處理時保存的, w!=0時取dword_8CA78，否則取dword_8CA7C
// 這裏面有很多函數， 其中還包括正向建立command_vdata過程，這裏略
sub_9d82(int n1, int n2, int n3, int w,  struct command_arg* arg, int* next_addr) {
	struct command_vdata* vdata = &dword_8CA7C; 
	if (w != 0) {
		vdata = &dword_8CA78;
	}
	
	// sub_9a14(command_vdata, n1, n2, n3, w, 0)
	// 最外層
	datalist = vdata->datalist;
	
	int i = 0;
	struct $8bitstruct* _8bitstruct = NULL;
	while(i < n1) {
		_8bitstruct = datalist[i]->d; // 取第一層8bitstruct指針
		int ra = _8bitstruct->command_arg1; // 第一層命令
		if (ra == n1) { // 第一層對比相等
			break;
		}
		i++;
	}
	// w不爲0，可能返回0x270F、0x26B0、0x26B1
	// 這裏暫不做分析
	if (_8bitstruct == NULL && w == 0) { // 沒找到的情況
		return 0x26b0;
	}
	//獲取第二層
	struct command_vdata* vdata1 = _8bitstruct->vdata;
	int count = vdata1->data_count;
	i = 0;
	struct $24bitstruct _24bitstr = NULL;
	while(i < count) {
		_24bitstr = vdata1->datalist[i]->d;
		int rb = _24bitstr->command_arg2;
		if (rb = n2) { // 第二層對比
			break;
		}
		i++;
	}
	// w不爲0，可能返回0x270F、0x26B0、0x26B1
	// 這裏暫不做分析
	if(_24bitstr == NULL && w == 0) { // 沒找到的情況
		return 0x26b0;
	}
	
	// 獲取第三層
	struct command_vdata* vdata2 = _24bitstr->vdata;
	count = vdata2->data_count;
	i = 0;
	struct $16bitstruct _16bitstr = NULL;
	while(i < count) {
		_16bitstr = vdata2->datalist[i]->d;
		int rc = _16bitstr->command_arg3;
		if(rc == n3) {
			int xor_addr = _16bitstr->xoraddr ^ _24bitstr->time;
			*next_addr = xor_addr;
			break;
		}
		i++;
	}
	typedef (*func)(void* void*) nfunc;
	nfunc nextf= (nfunc) next_addr;
	return nextf(command_arg, next_addr);
}
sub_9a14用
[stack]:BE892158 DCD 0xBE892180
[stack]:BE89215C DCD 0xB3D72771
[stack]:BE892160 DCD 0xACB6A748
[stack]:BE892164 DCD 0xBE89216C // r7 + 0xc
[stack]:BE892168 DCD 0x12DE5080
[stack]:BE89216C DCD 0

>> sub_9D60 結束

arg1 = command_arg->arg1;
跳轉到上面異或出來的地址処 // xor = time ^ sec; // B3E94525地址処，對應文件0x29524処‬
‬sub_2956C‬(command_arg, BE89216C); // 獲取傳遞參數arraylist 0xBE8921A0 -> 0x12E51660

env = command_arg->env;
jobjectarray = command_arg->args;
7E744‬ ->sub_7E784() // goto_getjarray_value
‬GetObjectArrayElement(env, jarray, index) // 返回jobject
在通過GetObjectClass獲取對應jclass，在調用GetMethodID獲取對應取元素的方法
在調用CallXXXMethod獲取數組中的value。

7E7EC‬(env, jarray, 1)->sub_7E830‬ // goto_getjarray_value1
functions->GetObjectArrayElement)()略，同上

sp + 4 = 第一個數組元素對應的值 
sp + 8 = 第二個數組元素對應的值 
// vvarg1
[stack]:BE892118 DCD 0xACB6A748                          ; sp0 command_arg
[stack]:BE89211C DCD 1                                   ; jarray value 1
[stack]:BE892120 DCD 1                                   ; jarray value 2
[stack]:BE892124 DCD 0xB47A9038
[stack]:BE892128 DCD 0xB3EF7A78                          ; command_vdata1
[stack]:BE89212C DCD 0
[stack]:BE892130 DCD 0xACB6A748 // ;command_arg
// vvarg2
[stack]:BE89216C DCD 0
[stack]:BE892170 DCD 0xB47A9038
[stack]:BE892174 DCD 0x2DF
[stack]:BE892178 DCD 0x75F91FF0
[stack]:BE89217C DCD 0x12DDD080
[stack]:BE892180 DCD 0x716162A0
[stack]:BE892184 DCD 0x12E51660
[stack]:BE892188 DCD 0xB4E07800
[stack]:BE89218C DCD 0xA44E7263
[stack]:BE892190 DCD 0x75F24BF8
[stack]:BE892194 DCD 0xBE892438
[stack]:BE892198 DCD 2
[stack]:BE89219C DCD 0x12C357C0
29FD4‬->sub_2A01E(vvarg1, vvarg2)‬

if (vvarg1[1] != 0)  { // 取第二個jarray的值， 這裏值為true
	r5 = vvarg1[0]; // 取第一個jarray的值
	// libsgmainso_6.4.36.so:B3E95042 BL              loc_B3E9DC00
	// 這應該是具體處理邏輯的函數了，分不分析無所謂了
	32C00()‬->sub_32C46(r5 = 1)‬;  { // 傳遞的jarray的第一個值
	// 邏輯我就不細緻分析了，這個就涉及到具體算法了，我不想去花時間在逆向算法上
	// 我們重點是搞清楚它都怎麽做的， 這裏我隨便記錄我想記錄的
	// 分不分析看心情
	30590->sub_305BE(1,0) 
		// 9來自程序中寫死的
		30240->sub_3026A(1,9)  // v2 = 1, v3 = 9 ; read_off_8AA50(off, index)
		// 讀取：off_8AA50[108]數組某處的值, 這個值可能是一個結構指針，後面邏輯會把它free
		// B3EF5A50 ; _DWORD dword_B3EF5A50[108]
		// B3EF5A50 DCD 0xB3EF7E18, 0xB3EF7E24, 0, 0xB3EF7E30, 0, 0, 0, 0xB3EF7E3C, 0xB3EF7E48
		// B3EF5A50 DCD 0xB3EF7E54, 0xB3EDE9D1, 0xB3EDE951, 0xB3EABEB9, 0, 0, 0, 0xB3EC2385
		// B3EF5A50 DCD 0, 0x14, 0, 0xB3ED48C1, 0, 0, 0xB3EF2AB6, 0xB3EF0C73, 0xB3EF0CC4, 0xB3EF0D15
		// B3EF5A50 DCD 0xB3EF2B08, 0xB3EDB6B1, 0, 0, 0, 3, 0x8AD2C, 2, 0x590, 0x17, 0x3B14
		// B3EF5A50 DCD 0x14, 0x11, 0x11, 0x2704, 0x12, 0x1410, 0x13, 8, 0x6FFFFFFA, 0x276
		// B3EF5A50 DCD 6, 0x18C, 0xB, 0x10, 5, 0x10FC, 0xA, 0xCA2, 4, 0x1DA0, 1, 0xC83, 1
		// B3EF5A50 DCD 0xC8D, 1, 0x15, 1, 0x5A1, 1, 0xC95, 1, 0x181, 0xE, 0x1D, 0x1A, 0x8A2E0
		// B3EF5A50 DCD 0x1C, 8, 0x19, 0x8AACC, 0x1B, 4, 0x1E, 8, 0x6FFFFFFB, 1, 0x6FFFFFF0
		// B3EF5A50 DCD 0x2498, 0x6FFFFFFC, 0x2688, 0x6FFFFFFD, 1, 0x6FFFFFFE, 0x26A4, 0x6FFFFFFF
		// B3EF5A50 DCD 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		// 第一次計算off_8AA50[9] = 0xB3EF7E54 = 文件偏移8CE54
		// 第二次計算 [0xB3EF7E54 + 4] =  0
		// libsgmainso_6.4.36.so:B3EF7E58 DCD 0
		v5 = *(_DWORD *)(off_8AA50[index] + 4 * off); 
		if ( v5 && *(_DWORD *)(v5 + 4) ) // 不成立
		  v6 = (*(int (**)(void))(v5 + 40))();
		else
		  v6 = 0;
		  // 返回0
		2D228->sub_2D1DA(1,9)->
			// goto_make_vdata6436
			sub_301BC(1,9) -> 301DE(index = 1, off = 9) 
			// 大字符數組
			// B3EF02FD aA0d11c6a829475d8 DCB "a0d11c6a829475d8",0
			// B3EF030E aC558656c6b70ed21 DCB "c558656c6b70ed21",0
			// B3EF031F aHardinfo DCB "hardinfo",0
			// B3EF0328 a9e83acb65377eab4 DCB "9e83acb65377eab4",0
			// B3EF0339 a835f56fa8c204d73 DCB "835f56fa8c204d73",0
			// B3EF034A a711718eb73d90dc5 DCB "711718eb73d90dc5",0
			// B3EF035B a68787a1ccce468bf DCB "68787a1ccce468bf",0
			// B3EF036C a999b23355c8909c1 DCB "999b23355c8909c1",0
			// B3EF037D aA9122d5b7873a0d3 DCB "a9122d5b7873a0d3",0
			// B3EF038E aD8b057995e905838 DCB "d8b057995e905838",0
			// B3EF039F a438e0bb7721e9d78 DCB "438e0bb7721e9d78",0
			// B3EF03B0 a570bfc082fe96042 DCB "570BFC082FE96042",0
			// B3EF03C1 aE87e68b3aea2d029 DCB "e87e68b3aea2d029",0
			// B3EF03D2 aEa6c627ab40979d1 DCB "ea6c627ab40979d1",0
			// B3EF03E3 a816f27e6be7ab193 DCB "816f27e6be7ab193",0
			// B3EF03F4 aB7b03fe1a0a13745 DCB "b7b03fe1a0a13745",0
			// B3EF0405 a4c60fa08664a7b66 DCB "4c60fa08664a7b66",0
			// B3EF0416 a624b4d174ad35f2d DCB "624b4d174ad35f2d",0
			// B3EF0427 a95ed8b0357989058 DCB "95ed8b0357989058",0
			// B3EF0438 a00f3acddd00fa671 DCB "00f3acddd00fa671",0
			// B3EF0449 a6c709c11d2d46a7b DCB "6c709c11d2d46a7b",0
			// B3EF045A aDd7893586a493dc3 DCB "dd7893586a493dc3",0
			// B3EF046B a58669b0e4dd2beb8 DCB "58669b0e4dd2beb8",0
			// B3EF047C a85d32f14e4edccf2 DCB "85d32f14e4edccf2",0
			// B3EF048D aE5c06c338bfa3568 DCB "e5c06c338bfa3568",0
			// B3EF049E a8dd236e3120fdbea DCB "8dd236e3120fdbea",0
			// B3EF04AF a8d8b035705995e98 DCB "8d8b035705995e98",0
			// B3EF04C0 a0357995e9858d8b0 DCB "0357995e9858d8b0",0
			// B3EF04D1 aPd DCB "pd",0
			// B3EF04D4 aDj DCB "dj",0
				// libsgmainso_6.4.36.so:B3EF59F8 dword_B3EF59F8 DCD 0xB3EF039F
				arg1 = 1, 獲得數組為off_8A9F8
				// libsgmainso_6.4.36.so:B3EF59D0 dword_B3EF59D0 DCD 0xB3EF02FD
				arg1 = 2, 獲得數組為off_8A9D0
				// libsgmainso_6.4.36.so:B3EF5A20 dword_B3EF5A20 DCD 0xB3EF0438
				否則，獲得數組為off_8AA20
				// 這裏為1，即off_8A9F8
				取字符串off_8A9F8[9] = "d8b057995e905838"
				// ACB1C9E0
				//7AF78 goto_create_vdata6436
				7AF78->sub_7AFB6(0x11) //參數是字符串長度+1,該函數實際上就是create_vdata6436
				// 實際上就是make_vdata6436
				// debug023:ACB1C938 DCD 0xACB6A5F8
				調用vdata6436->f1(vdata6436, "d8b057995e905838", 0x10);
			// 30240->sub_3026A(1,9)
			繼續調用goto_read_off_8AA50(1, 9) 得到結構指針為NULL
			// 7B148 goto_free_data
			7B148->sub_7B17A(0); // free_data; 執行free
			// goto_docommand_inner_contains_create_free_vdata32
			// ACB1C938; goto_create_vdata32; do_command_inner; free_vdata32
			30D24->sub_30D60(vdata6436,9,1,0,0,1); 
				7C218->sub_7C258("d8b057995e905838", 0x10) // geto_create_vdata32
					struct vdata32_nest {
						void* nf1;
						void* nf2;
						void* nf3;
						void* nf4;
					};

					struct vdata32 {
						struct data* data128;
						int data_count;
						int chunk_size;
						void* f1; // goto_make_vdata32;
						struct vdata32_nest* nest;
					};
					// debug018:ACB6A5C8
					7C0D4->sub_7C10C("d8b057995e905838", 0x10); // A1619860; create_vdata32
					7C280->sub_7C2C8(vdata32, "d8b057995e905838", 0x10); // goto_make_vdata32
				73D90 // 讀取off_90804{讀取off_xxx}的值x，這是之前保存起來的
				// debug018:ACB11E20 DCD 0xAFE7EA99
				// debug018:ACB11E24 DCD 0xAFE7EDF5
				// debug018:ACB11E28 DCD 0xAFE7EE49
			
				// 讀取[x + 4] = 0xAFE7EDF5，好像是fnPtr，後面跳到這個地址執行
				[stack]:BE892078 DCD 0xBE89207C // sp
				[stack]:BE89207C DCD 0
				[stack]:BE892080 DCD 0xA1619860 // vdata32
				{1, 0x15, 2, vdata32, 指向sp+4的指針}
				sub_9E30重新設置參數
				[stack]:BE892068 DCD 0xBE892080 sp
				[stack]:BE89206C DCD 0xBE89207C sp + 4
				走到9D60最終走到sub_9D82(1, 0x15, 2, 0, vdata32p, &saved_addrp) // command_native_inner
				// 不滿足查找條件，返回0x26b0
				存儲0x26b0到[stack]:BE89207C処
				[stack]:BE89207C DCD 0x26B0
				[stack]:BE892080 DCD 0xA1515580
				[stack]:BE892084 DCD 1
				[stack]:BE892088 DCD 7
				[stack]:BE89208C DCD 0xB47A9038
				[stack]:BE892090 DCD 1
				[stack]:BE892094 DCD 9
				[stack]:BE892098 DCD 0xBE8920AC
				[stack]:BE89209C DCD 0xB3C98207
				sub_9D82返回0x26b0
				7C34C->sub_7C3A4(vdata32) // free_data(vdata32); 沒用符合條件，vdata32就沒用到，把它free掉
				得到剛剛獲取的0x26b0並存儲
			7B148->sub_7B17A(0); // free_data; 執行free; free_vdata6436(vdata6436);
			
	32cc8->sub_32DC4(0,1,5,2)->sub_32DF0
		32F14{goto_read_off_8CE6C}->sub_32F44(1) ; // read_off_8CE6C(1)
		// B3EF7E6C ; _DWORD dword_B3EF7E6C[101]
		// B3EF7E6C DCD 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		// B3EF7E6C DCD 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		// B3EF7E6C DCD 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		// B3EF7E6C DCD 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		// B3EF7E6C DCD 0, 0, 0, 0, 0, 0, 0, 0, 0
		返回0
		32D78; // 調用5次goto_free_data, free掉查找到的結構指針, 應該是這個command用到的相關塊的結構
		
	7B148->sub_7B17A(0); // free_data; 執行free
	30240->sub_3026A(1,9); // 調用goto_read_off_8AA50(1); 同上略
	32cc8 // 繼續32cc8, 同上略
	}
}
	
	// goto_do_commandx
	2B468->sub_2B4BE()->73D90{讀取off_xxx值} // get_do_command_fnptr_str; 準備執行do_command_inner
	// 再次調試sub_9D60(1, 9, 2, 0, 0x6f, stackbuf = 0xBE8920CC)
	// 返回調用到0x9854后返回0x26b0保存到0xBE8920CC
	// 應該是讀取結構指針，然後釋放
	// 7B148->sub_7B17A(0); // free_data; 執行free 
	// 9DF4(1, 9, 2, 111) // 結果返回0，結束
	7AF78->sub_7AFB6(0x19) //參數是字符串長度+1,該函數實際上就是create_vdata6436
	調用vdata6436->f1(vdata6436, "000000000000000000000000", 0x18); // ACB1C938
	// goto_create_vstring
	7B5D4(vdata6436, "000000000000000000000000", 0, 0x30)->sub_7B606 // create_vstring ; AD2BEEE0
	29E98(stackbufp = BE8920EC, stack = BE89216C = NULL)->sub_11F3C(stackbufp, stack)
	*(BE8920EC + 12) = 0;
	*(BE8920EC) = 1;
	2ACB0->sub_2ACDE(arg = 1) // set_wt_flag; 如果arg <= 2 設置dword_8CE10為參數值
	304E4->(1,0,1)->sub_3052E(1, 0) // do_command_innerx1 
	//先get_do_command_fnptr_str 重新獲取下一個代碼塊，并執行
	// 此次獲取了之前構造保存的塊， ACB3B360
	// 再次執行do_command_inner(1, 8, 2, ...) 返回0
	30A04->sub_30A38(1)->
	2D504->sub_2D668(1)->2AC60->sub_2AC8A() ; // get_dword_8CE0C_classid
	// B3E986A2 BL              sub_B3E9DC00
	獲得dword_8CE0C = 0x1003F6; CallbackHelper
	再次調用32C00略 // 返回0, 實際也沒看到做什麽實質動作
	獲取env，sub_2D6B8調用解密
	解密出"onCallBack"， "(ILjava/lang/String;I)V"
	調用GetStaticMethodID(env, 0x1003F6, "onCallBack");
	調用CallStaticVoidMethod(JNIEnv*, 0x1003F6, onCallBack, 1, NULL, 0x386); 
	
------------------------------------------------------------------------------------------------------
經過這一系列的逆向發現原來sub_9B3C‬()這個函數是用來做建立和查找command處理的
最後把處理結果保存在一系列的嵌套的結構體中
這些結構體涉及上面提到的command_vdata， 8bitstruct， 16bitstruct，24bitstruct等
核心思路是把地址和一個隨機時間異或加密，然後把地址對應的command存儲在三層的結構體中
，這樣每次保持的地址和時間值都不一樣，反過來根據command來查找對應加密的梉，後面解密。

它記錄的地址實際還不是真正的程序地址，是梉，它還需要進一步去unpack才能進入真正的邏輯。

commandNative函數查找時，command 分爲三個主要參數 ：
command / 10000,
command % 10000 / 100,
command % 100
用這三個參數查找一個嵌套的結構體，找到與這三個結構體三層都一致的結構體
然後用之前記錄的時間和異或后的值再次異或就得到了跳轉地址。

