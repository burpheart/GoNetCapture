# GoNetCapture
 不依赖驱动的跨平台抓包工具

### 使用
windows 平台
```
GoNetCapture -a -f -x
-a 捕获网卡ip  默认127.0.0.1
-f pcap文件保存位置 默认 ./cap.pcap  文件已存在时会覆盖文件
-x 只打印HEXDUMP 不保存到文件

 * windows平台使用了winsock进行抓包 raw socket SIO_RCVALL
 * 抓包没有Eth头 固定全 00 MAC地址
```

linux 平台
```
GoNetCapture -f -x
-f pcap文件保存位置 默认 ./cap.pcap 文件已存在时会覆盖文件
-x 只打印HEXDUMP 不保存到文件

* linux平台使用的raw socket进行抓包
```

~~玩具项目 丢包很正常  能用就行~~ 