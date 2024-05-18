#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int packet_count = 0;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    packet_count++;
    printf("Packets captured: %d\n", packet_count);
}

int main() {
    char *dev = "en0"; // Replace with your network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "port 12001";
    bpf_u_int32 net;
    bpf_u_int32 mask;
    int buffer_size = 100 * 1024 * 1024; // 2 MB buffer size

    // Find the properties for the device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Create the pcap handle
    handle = pcap_create(dev, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't create pcap handle for device %s: %s\n", dev, errbuf);
        return(2);
    }

    // Set buffer size
    if (pcap_set_buffer_size(handle, buffer_size) != 0) {
        fprintf(stderr, "Couldn't set buffer size: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }

    // Set promiscuous mode
    if (pcap_set_promisc(handle, 1) != 0) {
        fprintf(stderr, "Couldn't set promiscuous mode: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }

    // Set timeout
    if (pcap_set_timeout(handle, 1000) != 0) {
        fprintf(stderr, "Couldn't set timeout: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }

    // Activate the pcap handle
    if (pcap_activate(handle) != 0) {
        fprintf(stderr, "Couldn't activate pcap handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return(2);
    }

    printf("Starting packet capture on interface %s with filter '%s'...\n", dev, filter_exp);

    // Start packet capture
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);

    return(0);
}
