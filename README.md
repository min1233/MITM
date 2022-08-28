# MITM Project

## Prepared Install (Require to use netfilter_queue)
### Install libnfnetlink
<pre>
<code>$ wget https://www.netfilter.org/pub/libnfnetlink/libnfnetlink-1.0.2.tar.bz2  
$ tar -xf libnfnetlink-1.0.2.tar.bz2  
$ cd libnfnetlink-1.0.2  
$ ./configure  
$ make  
$ sudo make install  
$ cd..</code>   
</pre>

### Install libmnl
<pre>
<code>$ wget https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2  
$ tar -xf libmnl-1.0.5.tar.bz2  
$ cd libmnl-1.0.5  
$ ./configure  
$ make  
$ sudo make install  
$ cd..</code>  
</pre>

### Install libnetfilter_queue
<pre>
<code>$ wget https://www.netfilter.org/pub/libnetfilter_queue/libnetfilter_queue-1.0.5.tar.bz2  
$ tar -xf libnetfilter_queue-1.0.5.tar.bz2  
$ cd libnetfilter_queue-1.0.5  
$ ls -l  
$ ./configure  
$ cd ..</code>  
</pre>

### Change Setting
<pre>
<code>$ sudo vi /etc/ld.so.conf  
include /usr/local/lib  
$ sudo ldconfig</code>  
</pre>

### Set Iptables
Transfer from TCP 80 port and 443 port on FORWARD to netfilter_queue
<pre>
<code>$ sudo iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE
$ sudo iptables -A FORWARD -p tcp --dport 443 -j NFQUEUE
$ sudo iptables -A FORWARD -p tcp --sport 80 -j NFQUEUE
$ sudo iptables -A FORWARD -p tcp --sport 443 -j NFQUEUE</code>
</pre>

## ARP Spoofing
<a href="https://github.com/min1233/arp_spoofing">Project Link</a>
