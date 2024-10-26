上面一篇写到了JAVA层到JNI层的入口细节，这一篇就从JNI开始写。

sub_CC50函数很快就会遇到一个BX R2的跳转寄存器地址，导致无法反编译到C代码。这个我在前面的文章里面说过方法，即hook当前寄存器值，查看相应的值，然后Patch掉相应的代码，即可以查看。



但相应的要注意的地方是，要注意这个位置的跳转有几个，跳转的位置是否相同，这直接影响到你分析逻辑的细节。

比如我分析的逻辑到这里只有一个跳转，直接Patch即可。然后就可以相对愉悦地查看C的伪代码了。



然后，我们就可以发现，决定接下来逻辑跳转方向的，即为我们传入的code值。

程序会将code做几个操作，将code分解成几个值，再将其赋值给一个结构体：

```c++
int aInt = code / 10000;
int bInt = code % 10000 / 100;
int cInt = code % 100;

struct sub_cc51_v7_data {
    int aInt;
    int bInt;
    int cInt;
    JNIEnv *env;
    int argObj;
}

sub_cc51_v7_data v7_data;

v7_data->aInt = aInt;
v7_data->bInt = bInt;
v7_data->cInt = cInt;
v7_data->JNIEnv = env;
v7_data->argObj = (int)objArr;
```

然后再调用 void sub_9EFC(int a1, int a2, int a3, int a4, struc_cc51_v7_data *a5, int a6)函数。

而更重要的逻辑跳转，则位于sub_9EFC函数中......

而接下来的内容，研究方向不同，方法也就不尽相同了。

结语：

我最近学习和研究的逻辑，在sub_9EFC中做了5次跳转，其中有3个不同的位置。可以说是相当核心的一个位置了。

而这个跳转位置，会提前根据相关的逻辑计算好，放在堆栈指针寄存器sp中，仅靠简单的伪代码无法完全还原出来。

具体的操作，还要看具体的思路了。

