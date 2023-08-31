#ifndef CLICK_OMNISTACK_FIREWALL_HH
#define CLICK_OMNISTACK_FIREWALL_HH
#include <click/batchelement.hh>
#include <cstdint>

struct FireWallItem {
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    uint8_t src_cidr;
    uint8_t dst_cidr;
    uint32_t src_cidr_mask;
    uint32_t dst_cidr_mask;
    uint32_t src_port;
    uint32_t dst_port;
    uint16_t nic;
    uint16_t* l2_proto;
    uint8_t* l3_proto;
    uint32_t l2_proto_count;
    uint32_t l3_proto_count;

    void Init();
};

CLICK_DECLS

class OmniStackFireWall : public BatchElement {
    public:

        OmniStackFireWall() CLICK_COLD;
        ~OmniStackFireWall() CLICK_COLD;

        const char *class_name() const override    { return "OmniStackFireWall"; }
        const char *port_count() const override    { return PORTS_1_1; }

        int configure(Vector<String> &conf, ErrorHandler *errh);

        Packet      *simple_action      (Packet *);
    #if HAVE_BATCH
        PacketBatch *simple_action_batch(PacketBatch *);
    #endif

    private:
        FireWallItem white_list_[64];
        FireWallItem black_list_[64];

        int white_list_size_ = 0;
        int black_list_size_ = 0;

        bool use_white_list_;
};

CLICK_ENDDECLS
#endif // CLICK_ETHERMIRROR_HH
