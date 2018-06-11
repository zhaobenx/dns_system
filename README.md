# Experimental DNS server and client

## Brief

Works only on Linux. Windows is not supported.

This is a simple DNS server, local server and client. The message can be sniffered by wireshark. It also support Chinese domain name.  This project provide A, MX and CNAME type query and response.

But the compression pointer is not supported.

Servers work on UDP; messages between client and local server work on TCP; messages btween server and local server is UDP DNS message.



## Usage

```bash
make
sudo make test
```

And open another shell, run

```bash
./client www.baidu.com
./client -mx www.baidu.com
./client 北邮.教育.中国
```

