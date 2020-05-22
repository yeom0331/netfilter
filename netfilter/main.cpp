#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <iostream>
#include "netfilter.h"
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;
static bool cheak=false;
static char* target;
static int target_size;

void usage() {
    printf("syntax : netfilter_block\n");
    printf("sample : netfilter_block test.gilgil.net\n");
}

bool find_site(unsigned char *data){
    struct libnet_ipv4_hdr *ip=(struct libnet_ipv4_hdr*)data;
    if(ip->ip_p != IPPROTO_TCP){
        return false;
    }
    int ip_len = ip->ip_hl*4;
    struct libnet_tcp_hdr *tcp=(struct libnet_tcp_hdr*)(data+ip_len);
    int tcp_len=tcp->th_off*4;
    int payload_len = ntohs(ip->ip_len)-ip_len-tcp_len;
    if(payload_len==0){
        return false;
    }
    char *http_start=(char*)data+ip_len+tcp_len;

    string s(http_start,payload_len);

    if(memcmp(http_start, "GET ", 4)==0 || memcmp(http_start, "POST", 4)==0){
        size_t host_find = s.find("Host");
        if(host_find!=string::npos){
            string url = s.substr(host_find+6,target_size);
            for(int i=0;i<target_size;i++){
                if(target[i]==url[i]){
                    return true;
                }
                return false;
            }
        }
        return false;
    }
    return false;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        //printf("hw_protocol=0x%04x hook=%u id=%u ",
           // ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        //int i, hlen = ntohs(hwph->hw_addrlen);

        //printf("hw_src_addr=");
        //for (i = 0; i < hlen-1; i++)
            //printf("%02x:", hwph->hw_addr[i]);
       // printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        //printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        //printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        //printf("payload_len=%d ", ret);
        cheak= find_site(data);
    }
    //fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    //printf("entering callback\n");

    if(cheak==true) {
        printf("blocked\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    if(argc!=2){
        usage();
        return -1;
    }
    target=argv[1];
    target_size=strlen(target);
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //printf("pkt received\n");
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

    printf("unbinding from queue 0\n");
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
