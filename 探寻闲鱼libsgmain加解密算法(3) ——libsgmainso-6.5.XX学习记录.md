# 探寻闲鱼libsgmain加解密算法(3) ——libsgmainso-6.5.XX学习记录

闲鱼的libsgmainso其实和淘宝的本质上差不多，同样是用来做为应用安全防护、生成请求签名，以及很多后端数据加解密的模块。

应用解压后可以在lib目录下直接看到libsgmain.so文件，但这个so本质上是一个apk，其中com.alibaba.wireless.security.mainplugin.SecurityGuardMainPlugin
类中加载真正的libsgmainso-6.5.xx.so。而这个so文件，才是正主，做为动态链接库，提供给整个应用做很多“大事”。

## 一、加载

如果你看过做为apk的libsgmain.so文件，可能会了解真正的libsgmain-6.5.xx.so的加载过程其实是动态注册，其加载入口和调用的位置都在com.taobao.wireless.security.adapter.JNICLibrary类。

```java
package com.taobao.wireless.security.adapter;
 
/* loaded from: classes.dex */
public class JNICLibrary {
    public static native Object doCommandNative(int i, Object... objArr);
}
```

其中的doCommandNative(int i, Object... objArr)方法，即是加载、初始化的方法，也是整个应用调用so函数的入口方法。

使用frida或者xposed很容易就可以在这个位置得到整个调用过程（下方只是一个示例，隐去了部分关键版本信息）：

```
{'type': 'send', 'payload': 'loader = dalvik.system.PathClassLoader[DexPathList[[zip file "/data/app/com.taobao.idlefish-xxxx/lib/arm/libsgmain.so"],nativeLibraryDirectories=[/data/app/com.taobao.idlefish-xxxx/lib/arm, /data/user/0/com.taobao.idlefish/app_SGLib/app_xxxx/main, /system/lib, /vendor/lib]]]'}
------------------------------------------------------------
{'type': 'send', 'payload': ' #### >>> a = 10101\n #### >>> Obj = com.taobao.idlefish.TaoBaoApplication@62684fc,3,,/data/user/0/com.taobao.idlefish/app_SGLib,\n #### >>> rc= 0\n '}
------------------------------------------------------------
{'type': 'send', 'payload': ' #### >>> a = 10102\n #### >>> Obj = main,6.5.24,/data/app/com.taobao.idlefish-xxxx/lib/arm/libsgmainso-6.5.xxxx.so\n #### >>> rc= 0\n'}
------------------------------------------------------------
{'type': 'send', 'payload': ' #### >>> a = 10102\n #### >>> Obj = securitybody,6.5.xxxx,/data/app/com.taobao.idlefish-xxxx/lib/arm/libsgsecuritybodyso-6.5.xxxx.so\n #### >>> rc= 0\n '}
```





## 二、调用

Java层调用JNI层的入口，同样是doCommandNative(int i, Object... objArr)方法，只是参数不同。当JNI层初始化完成以后，整个程序的的很多功能即可以通过调用doCommandNative方法实现，而这些所有的实现，就都转入了native层实现了。

比如我们最多用到的请求签名：

```
{'type': 'send', 'payload': ' #### >>> a = 70102\n #### >>> Obj = 21407387,******************&&&21407387&99914b932bd37a50b983c5e7c90ae93b&***timestamp***&mtop.common.gettimestamp&*&&263200@fleamarket_android_x.x.xx&Ahy0caUpskAQYpKimD1xjECT-nLK3HDoIbE-YrrMA954&&&openappkey=DEFAULT_AUTH&27&&&&&&&,false,0,mtop.common.gettimestamp,pageId=&pageName=,,,\n #### >>> rc= {x-sgext=JAGEZrpW7llC1awdzI/+2Ga1VrVUtEWyV7BVp1SnRbVRtFO3VrBVt1Q=, x-umt=4F8BRv1LPKvXcAKNC9ptrUyO+LlgqQDT, x-mini-wua=HHnB_8z4ie/gna+8A4/FYXnYbFH5f3el2JOQdHu3STjGutnRhMYRgX9nG6+sCGNzGiGhpZejPT3GKndcR4W3U0TGNyNzggt2bB70ypwmLkTODjS2oNxaZ+MGVMyY0ms5bHrQTdRoqlxHyxbbSthbGmvmkoeTad4QH29GcyzVNTy1egJk=, x-sign=azU7Bc002xAALN7NqXUJ4QCDEEF+7N7M3hFkioluJQTAyS7YsRhtBmO73uQOcXgWCgQxR0jGTsHthhqwjv2auH+If1ze3N7M3tzezN}'}
```



## 三、JNI层

前面说过整个so都是通过动态注册的形式引入、加载，然后调用的。所以即使拿到so文件，入到IDA里面，也是看不到我们想象的`Java_com_taobao_wireless_security_adapter_JNICLibrary_doCommandNative`的导出函数的。



在导出列表中搜索Java_， 根本没有结果，搜索"J"的结果如上，只可以看到 JNI_OnLoad等函数，看不到我们想要的调用。

所以，还需要hook RegisterNatives，用来确定JNI函数的入口位置：

`[RegisterNatives] java_class: com.taobao.wireless.security.adapter.JNICLibrary name: doCommandNative sig: (I[Ljava/lang/Object;)Ljava/lang/Object; fnPtr: 0xb80d4c51  fnOffset: 0xb80d4c51 libsgmainso-6.5.xxxx.so!0xcc51`
可以看到入口函数的偏移位置为0xcc51, 因为是IDA反编译后显示thumb指令，所以放在IDA中的位置即为 0xcc50。



如果用Unidbg查看这里的内存情况，即可以看到相应的参数：
```
mr0
>-----------------------------------------------------------------------------<
>[21:20:00 473]r0=unidbg@0xfffe12a0[libandroid.so]0x2a0, md5=30ced1c5a26150fdc5b5baf3572a24c6, hex=f00efeff000000000000000000000000e60100ef1eff2fe10000000000000000e70100ef1eff2fe100000000000000000000000004000000080000000c000000b012feff14000000c012feff1c000000e80100ef1eff2fe10000000000000000e90100ef1eff2fe10000000000000000
>size: 112
>0000: F0 0E FE FF 00 00 00 00 00 00 00 00 00 00 00 00    ................
>0010: E6 01 00 EF 1E FF 2F E1 00 00 00 00 00 00 00 00    ....../.........
>0020: E7 01 00 EF 1E FF 2F E1 00 00 00 00 00 00 00 00    ....../.........
>0030: 00 00 00 00 04 00 00 00 08 00 00 00 0C 00 00 00    ................
>0040: B0 12 FE FF 14 00 00 00 C0 12 FE FF 1C 00 00 00    ................
>0050: E8 01 00 EF 1E FF 2F E1 00 00 00 00 00 00 00 00    ....../.........
>0060: E9 01 00 EF 1E FF 2F E1 00 00 00 00 00 00 00 00    ....../.........
>^-----------------------------------------------------------------------------^

r0 为 JNIEnv *env的指针， r1 为jclass的指针， r2 为传入的指令代码如70102的16进程，r3为 objArray的hashCode.


>>> r0=0xfffe12a0(-126304) r1=0x86f3d40b r2=0x2969 r3=0xbef2d72 r4=0x0 r5=0x0 r6=0x0 r7=0x0 r8=0x0 sb=0x0 sl=0x0 fp=0x0 ip=0x2710
>>> SP=0xbffff720 LR=unidbg@0xffff0000 PC=RX@0x4000cc50[libmain.so]0xcc50 cpsr: N=0, Z=1, C=1, V=0, T=1, mode=0b10000
>>> d0=0x6e69616d67736234(7.339530223887578E223) d1=0x322e352e362d6f2e(5.602336079605977E-67) d2=0x6c64692e6f616273(1.3742582103009832E214) d3=0x55612d687369666f(1.9236467718641197E103) d4=0x724e75796337357a(4.0620054927062685E242) d5=0x37484375366f776d(2.176026590763671E-42) d6=0x6c2f3d3d67304f38(1.3145802649595892E213) d7=0x6c2f6d72612f6269(1.3225044853944435E213)
>>> d8=0x0(0.0) d9=0x0(0.0) d10=0x0(0.0) d11=0x0(0.0) d12=0x0(0.0) d13=0x0(0.0) d14=0x0(0.0) d15=0x0(0.0)

```
下面为Unidbg打印的当前位置的参数信息：

```
[2024-10-26 21:19:24] [main] INFO com.core.Debug - envPointer: unidbg@0xfffe12a0[libandroid.so]0x2a0
[2024-10-26 21:19:24] [main] INFO com.core.Debug - jclsPointer: unidbg@0x86f3d40b
[2024-10-26 21:19:24] [main] INFO com.core.Debug - intArg: 0xxxxx
[2024-10-26 21:19:24] [main] INFO com.core.Debug - objArray: [java.lang.Integer@69b2283a, java.lang.Integer@22a637e7, java.lang.Integer@6fe7aac8, "xxxxxxxx", [B@1d119efb, ""]
```




未完待续...
