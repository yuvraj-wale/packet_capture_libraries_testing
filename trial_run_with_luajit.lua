local ffi = require("ffi")

ffi.cdef[[
typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;
typedef unsigned char u_char;

typedef struct pcap_pkthdr {
    struct timeval {
        long tv_sec;
        long tv_usec;
    } ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
} pcap_pkthdr;

typedef struct pcap_if_t {
    struct pcap_if_t *next;
    char *name;
    char *description;
    struct pcap_addr *addresses;
    bpf_u_int32 flags;
} pcap_if_t;

typedef struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr *addr;
    struct sockaddr *netmask;
    struct sockaddr *broadaddr;
    struct sockaddr *dstaddr;
} pcap_addr;

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn *bf_insns;
};

char *pcap_lookupdev(char *);
char *pcap_geterr(pcap_t *);
pcap_t *pcap_open_live(const char *, int, int, int, char *);
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const u_char **);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32);
int pcap_setfilter(pcap_t *, struct bpf_program *);
void pcap_freecode(struct bpf_program *);
int pcap_loop(pcap_t *, int, pcap_handler, u_char *);
void pcap_close(pcap_t *);

// This is not a standard function, but checking if it exists
int pcap_set_buffer_size(pcap_t *, int);
]]

local pcap = ffi.load("pcap")

local function capture_packets(interface, port)
    local errbuf = ffi.new("char[256]")
    local handle = pcap.pcap_open_live(interface, 65536, 1, 1000, errbuf)
    local packet_count = 0

    if handle == nil then
        print("Error opening device: " .. ffi.string(errbuf))
        return
    end

    -- Attempt to set the buffer size if the function is available
    if pcap.pcap_set_buffer_size then
        if pcap.pcap_set_buffer_size(handle, 100 * 1024 * 1024) == -1 then
            print("Error setting buffer size: " .. ffi.string(pcap.pcap_geterr(handle)))
        else
            print("Buffer size set successfully")
        end
    else
        print("pcap_set_buffer_size function not available")
    end

    -- Compile and set the filter
    local filter = string.format("port %d", port)
    local bpf_program = ffi.new("struct bpf_program")
    if pcap.pcap_compile(handle, bpf_program, filter, 0, 0) == -1 then
        print("Error compiling filter: " .. ffi.string(pcap.pcap_geterr(handle)))
        pcap.pcap_close(handle)
        return
    end

    if pcap.pcap_setfilter(handle, bpf_program) == -1 then
        print("Error setting filter: " .. ffi.string(pcap.pcap_geterr(handle)))
        pcap.pcap_freecode(bpf_program)
        pcap.pcap_close(handle)
        return
    end

    pcap.pcap_freecode(bpf_program)

    local packet_handler = ffi.cast("pcap_handler", function(user, hdr, data)
        packet_count = packet_count + 1
        print("Captured packet number: " .. packet_count)
    end)

    if pcap.pcap_loop(handle, 0, packet_handler, nil) == -1 then
        print("Error capturing packets: " .. ffi.string(pcap.pcap_geterr(handle)))
    end

    pcap.pcap_close(handle)
end

-- Capture packets on interface 'en0'
capture_packets("en0", 12001)
