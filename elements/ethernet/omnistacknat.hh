#ifndef OMNISTACK_NAT_HH
#define OMNISTACK_NAT_HH

#include <click/batchelement.hh>
#include <click/hashmap.hh>
#include <click/memorypool.hh>
#include <cstdint>

struct OSNATItem {
    uint32_t ipv4;
    uint16_t ori_port;
    uint16_t new_port;
};

CLICK_DECLS

class OmniStackNAT : public BatchElement {
	public:

		OmniStackNAT() CLICK_COLD;
		~OmniStackNAT() CLICK_COLD;

		const char *class_name() const override    { return "OmniStackNAT"; }
        const char *port_count() const override    { return PORTS_1_1; }
        int configure(Vector<String> &conf, ErrorHandler *errh);

        Packet      *simple_action      (Packet *);
    #if HAVE_BATCH
        PacketBatch *simple_action_batch(PacketBatch *);
    #endif

    private:
        HashMap<uint16_t, void*> *nat_map_;
        MemoryPool<OSNATItem> *nat_pool_;
};

CLICK_ENDDECLS

#endif
