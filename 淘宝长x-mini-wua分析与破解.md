# 淘宝长x-mini-wua分析与破解



## 前言

淘宝的x-mini-wua中带着硬件参数 

如果是新设备 则可以不带账号获取一些淘宝商品的数据 

如果能生成海量的wua那岂不是可以无限不带账号拿数据？

好了开始分析 样本21年的某宝

本文并不会贴出对应的算法 只会一带而过 重点是mini-wua生成的流程

以下代码快内容都人工加了**和谐**二字

## SG_INNER_DATA 分析

真机关闭网络后只会生成短wua和短umt 那么说明肯定是走了网络请求

发现某宝会读取本地 data\user\0\com.taobao.taobao\app_SGLib\SG_INNER_DATA

文件里面存放这AES加密后的数据 通用固定key 16位

```json
// 原文过长大部分删除了{"SGTMAGIC":"A4Zgd/OU1poS/0vNsfiKU+mdS3LdmQqHbae5EwzDgq0=","SGSAFETOKEN_IN":"21c2&20n8wkqcYc5cQb+nyCa9br571kglq5BB7JqHddGd4gSVUavHTWJXNOGEMX33dMSafN7C0pwpTPfgqBLiajKe6Y50TFXyzEQp4kgXFpiqo0KNRmH69zQD4hpj7efyX/3uMxDj28U1W7iBYbvAqOIuU5WcKO0ah2pMHnOaHu2Q7nOtPKVXS5iJ3H5A59eWnsoZLYiQg7l5d/+0ZdCJK/Uu8uSIlnrOfHaW3PiBp/RYPIu+X和wM5xZObiMwVk0ft76guJSaTwH/1xTUiJ4vBZHzB5+9nDvUxeSZLKFTGrtQHg+NLRCW92FdqbcFrbjrUDFJ87LwoK4v8P2b8qK/+/m70Jj8yd3RFx51t9LDjlVoB5wk+Dcd5hso7GsplCqLIgebHKACz4C7HVvmVqRhA+WeCCG0GMNdOygw78M6qV3wRy+uL7u2+mZvyVm6OUKmy/tjH0y6pva8kkDgysEAzWbjVR----------------和谐-----------------------pWTaoVtGqr2qEW0I/Mr8IjZ94/EItec3+Pwe9eISyDFr19Mp0JprO8RPpcqKPC6Me/K0wnCOREJqWmfSJh1CrTCu8dzHBW75InVpvBf1c7HAI6u6f0DG92r5n/f89gzmopu9FzgHnyG9kJwnMWCeN6dKxbaIa3ASxQxSV7HYqga1jNw3kVS7ydtTVftiSdvkVhudzUK463+lmDoJSQZb6WCFgLL39Bbde9lSOil20p2FdBcm2GpzPSB5bngR16L/48dkzd5z7v2HcTozzUoqkE4N8Fq3vbK0y9WmtJTh/xrw2kwUGjbKEP1uZ989ZSfeY63LERRbSPNxitzrhmwoXrGDU1ekyTYCPnztdYZxjug2QPUX9ga1ieg0khBaDMeI5umvVa/yK4bYUHhistUS6jjZPYPbCN6zd2RMEZNeBPWRcu8h4mxUpd9BqaYzS9163PlFCa90afTNcZ624cnyPEfeM7I0BOiLKmDCIM3rk81okSt2GO+koRr/Tu3zfL270eGnd5G/wB1RggXPlzB6ey9/rviOcMYRt6Im6c52QmXO/+Ujcw0t7DYUPRjx5GtQInGWKKQ=="}
```



第一次解密后的json

```json
{"stid45-0":"009&2d093cae1uzuMmnV56K58和谐hjMiHMHuAV1u+5/qELw7qd/tiyE5ERFacYBFet","rt_undef_key0":"009&2d093caeBNnSnHUsyROVLnJCr+SPLaNGBWpDLBrkUK3JeM7IfV0iILDIjK+IlO7g4upcifbDArHBz9I86V0HeHl0vYkl/Cz8Z4GvUsNB8am9B1rnvVoMgc/l6pTgBvOrNeoBvi5rh59nQ+nuJTj6AhTA5SMusKl894r4eHK8kbLC6gejw1g=","rt_local_storage0":"009&2d093cae1zlYXB0ny6j+r和谐6eNU18wwvVAI1lnpFz/uJLY5M2k2O82Kko4N5qnL4/gYT6zP3pMmKu8Mpiy9pmsH35VO2k4uXezRbf15bYTee/Y4iYHiqerdfkGif1fwXpzju和谐a8olX7hY6/FiEPunlTF4ANg8KslK7MMuuRrDJP6vS4aXZ8jvhlRFiFkry5poMdEQT+EposVosr+PEqVxEew09qRWnxNLBGZ9HkBLnYPCmGsZoqdBogPEyveYD094vb7RGvQgvQl和谐jhneuAD4LZkKRRIjhmBfTmYgi/XoAKO0WYP4Hda/jSD3MGzQoK6gqf21IvtHYzf7p5hfrGRnFOlTVUia5","wua_config_rconfig":"009&2d093caecVJe1qYEb0N+f8IbX4xoR3ozpwVAPFUUVjJL+4ZlAtlLVqWyE9qMAIF/eILU6LRlazOxUeuRXaXhmqXmpawe6ERNwvs1PAIIe+houZqm+o4=","rck":"009&2d093caeaYBQGF/eMY9o3FP0BIer5Rgs6vZK0DlvhX79dRmWQxRLWikhA+Hz8ap8UD249Yht","sdfsd-0":"009&2d093caeJQEbwv2sh9urJKQi/ZZpxue/RxK和谐OkmocSABJq0K/9MqenWXKnqUkDcKdidna/s0abMt3ucI+lsyGxQPxn42qVh4FxuzxACvMe7wLVGS6c7vfY2pcLtPvvCX3coNnZNzG6vaDFhu5FbDYKeWjgh7bBxnCsX4C0Fkfhw=","rt_cdn_url0":"009&2d093caeJSGwB0Dqusg8zc88SDRcH和谐gJKRIY3n/zTHbH8cl3HihOPoR1/Z9sBnH2YG8","lastSplReqTime":"009&2d093caeIcKXRJSP2RA9F1H8lpWlCA=="}
```



二级解密 key计算规则 xxxxx-型号-com.taobao.taobao-inode

```
stid45-0解密后:JUGAjpFLPIas和谐KDFb64OmfA6hVyh+o1
sdfsd-0解密后:M1gAV4yYmWsMjJC3QiFOrilMVDvc0和谐2sTzPRbgMq99E0XYF6W2eq9G0ads0和谐r42h3HyQ0pzCQ/EbdxChpSb2q3和谐Bi9ut8TDSq7fV/txQdBUQ==
```

stid45-0=umt **sdfsd-0=长wua** 
至于其他几个json key的解密就不贴了
 

app刚打开的时候只会有rt_undef_key0 发完硬件信息请求拿到M1g 

才会加密写入SG_INNER_DATA内 

本地的算法只能生成短wua 

必须读取到sdfsd=eeid才会生成长wua

## 协议（部分）

好几条请求 
基本都是上报硬件信息及手机环境等 
权限给的越多 
上报的硬件信息则会增加

```java
jsonObject.put("403e",setSV("5e07","sirius")); //设备
jsonObject.put("aaca",setSV("5e07","MI 8 SE")); //型号
jsonObject.put("b07c",setSV("5e07","sdm710")); //处理器
jsonObject.put("2b23",setSV("5e07","Xiaomi")); //品牌
jsonObject.put("2b09",setSV("5e07","OPM1.171019.019")); //Build ID
jsonObject.put("f471",setSV("5e07","8.1.0")); //android版本
jsonObject.put("b8c8",setSV("5e07","release-keys"));
jsonObject.put("f31c",setSV("5e07","27")); //SDK
jsonObject.put("0048",setSV("cecf","864111111112756")); //IMEI
jsonObject.put("1090",setSV("cecf","460000000000002"));
jsonObject.put("79c0",setSV("cecf","890000009060006700023"));
jsonObject.put("aaa0",setSV("cecf","1080*2114"));
jsonObject.put("a2c2",setSV("cecf","1080*2244")); //分辨率
jsonObject.put("1462",setSV("cecf","MPSS-SDM710-0727_1666_2b0e169")); //基带版本
jsonObject.put("f02e",setSV("cecf","中国联通"));
 
//指纹
jsonObject.put("fd52",setSV("5e07","Xiaomi/sirius/sirius:8.1.0/OPM1.171019.019/V9.5.51.0.OEBCAFA:user/release-keys"));
jsonObject.put("8fdc",setSV("5e07","sirius-user 8.1.0 OPM1.171019.019 V9.1.12.0.OEBCNFA release-keys"));
jsonObject.put("1cdb",setSV("5e07","c3-miui-ota-bd188.bj"));//Build Host
jsonObject.put("3b0a",setSV("5e07","V9.8.22.0.OEBCNFA"));//incremental
```

```java
"0864": [
{
"s": "e097",
"v": "00:18:48:3d:b3:33"
},
{
"s": "9487",
"v": "(dummy0)4a:80:1b:19:b5:0a"
},
{
"s": "98e9",
"v": "(wlan0)2a:e2:d7:6e:ed:a6(rmnet_data0)00:00:00:00:00:00(dummy0)4a:80:1b:19:b5:0a"
},
{
"s": "cecf",
"v": "2A:E2:D7:6E:ED:A6"
}
],
"a506": [
{
"s": "cecf",
"v": "1662518624366"
},
{
"s": "7c1c",
"v": "{\"/data\":\"2CDB31062CDB31062CDB31162CDB31062CDB31062CDB3106\",\"/dev\":\"27923A2917923A2927923A2927923A2927823A2927923A29\",\"/storage\":\"2947AA002947AA003047AA002947AA002947AA002947AA00\"}"
}
],
```



完整json分三个部分ct内容包含了以上硬件信息相关 

我们只要对整个json数据逐一分析 

用随机的硬件信息或真机库数据进行动态修改并发送请求 

即可获取大量eeid **短wua算法+eeid=长wua**

## 发送请求

所有参数破解后生成完整josn加密 head带上4个基础签名x-umt x-sign x-sgext 短x-mini-wua进行请求

![请求eeid](https://github.com/FightingForWhat/taobao-reverse-documents/blob/main/img/eeid-request.jpg)

Gzip一下然后再解密返回数据

![请求eeid](https://github.com/FightingForWhat/taobao-reverse-documents/blob/main/img/eeid-response.jpg)



## 总结

**真机无root xp frida生成的eeid可以用反之环境异常手机则不行**

拿着eeid生成完整4签名即可不带账号获取到商品详情数据

还有一些细节没有完善 以及大量请求风控之类的 我不爬淘宝数据

只想研究下这种结合服务端的签名算法 也是头一次搞 很有意思

改机的彻底应该也能过 就是效率低了些 对wua感兴趣的可以去研究libsgmainso.so



