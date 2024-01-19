## net-Sniffer
网络协议分析实验作业， 基于PyQt5 和 Scapy 实现的简易网络嗅探器.
仅测试Linux下使用

使用前需配置网卡，可以选择过滤(默认捕获全部数据包)， 过滤数据包使用BPF (Berkeley Packet Filter) 表达式， 然后点击开始按钮开始过滤， 点击停止按钮停止捕获，重置按钮能清空以捕获数据包， 保存按钮可以将捕获的数据包保存成pcap格式， 点击info栏可以查看详细信息。

依赖要求： python3 scapy PyQt5 libreport



![](/img/demo.gif)
