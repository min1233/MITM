# MITM Project

## Prepared Install (Require to use pcap.h, pthread.h)
### Install libnfnetlink
<code>  
$ wget https://www.netfilter.org/pub/libnfnetlink/libnfnetlink-1.0.2.tar.bz2  
$ tar -xf libnfnetlink-1.0.2.tar.bz2  
$ cd libnfnetlink-1.0.2  
$ ./configure  
$ make  
$ sudo make install  
$ cd..  
</code>   

### Install libmnl
<code>  
$ wget https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2  
$ tar -xf libmnl-1.0.5.tar.bz2  
$ cd libmnl-1.0.5  
$ ./configure  
$ make  
$ sudo make install  
$ cd..  
</code>  

### Install libnetfilter_queue
<code>  
$ wget https://www.netfilter.org/pub/libnetfilter_queue/libnetfilter_queue-1.0.5.tar.bz2  
$ tar -xf libnetfilter_queue-1.0.5.tar.bz2  
$ cd libnetfilter_queue-1.0.5  
$ ls -l  
$ ./configure  
$ cd ..  
</code>  

### Change Setting
<code>  
$ sudo vi /etc/ld.so.conf  
include /usr/local/lib  
$ sudo ldconfig  
</code>  
