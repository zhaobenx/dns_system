all : client server localServer
.PHONY : all
client : client.c dns.h dns.c
	gcc -std=c99 client.c dns.c dns.h -o client
server : server.c dns.h dns.c
	gcc -std=c99 server.c dns.c dns.h -o server
localServer : localServer.c dns.h dns.c
	gcc -std=c99 localServer.c dns.c dns.h -o localServer
	
clean:
	rm client
	rm server
	rm localServer
	
test:
	sudo ./server 127.1.1.1 >> 127.1.1.1/log&
	sudo ./server 127.2.2.1 >> 127.2.2.1/log&
	sudo ./server 127.3.3.1 >> 127.3.3.1/log&
	sudo ./server 127.4.4.1 >> 127.4.4.1/log&
	sudo ./server 127.5.5.1 >> 127.5.5.1/log&
	sudo ./server 127.6.6.1 >> 127.6.6.1/log&
	
	echo "Open another shell and run ./client www.baidu.com to test"
	echo "./client -mx www.baidu.com "
	echo "./client -mx 北邮.教育.中国 "
	echo "./client 北邮.教育.中国 "
	sudo ./localServer