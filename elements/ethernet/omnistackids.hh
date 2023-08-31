#ifndef OMNISTACK_IDS_HH
#define OMNISTACK_IDS_HH

#include <click/batchelement.hh>

struct ACANode {
    ACANode() {
        memset(son, 0, sizeof(son));
        fail = nullptr;
        count = 0;
    }

    ACANode* son[256];
    ACANode* fail;
    int count;
};

CLICK_DECLS

class OmniStackIDS : public BatchElement {
	public:

		OmniStackIDS() CLICK_COLD;
		~OmniStackIDS() CLICK_COLD;

		const char *class_name() const override    { return "OmniStackIDS"; }
        const char *port_count() const override    { return PORTS_1_1; }
        int configure(Vector<String> &conf, ErrorHandler *errh);

        Packet      *simple_action      (Packet *);
    #if HAVE_BATCH
        PacketBatch *simple_action_batch(PacketBatch *);
    #endif

    private:
        ACANode* root = nullptr;

        void AddPatternString(const String&);
};

CLICK_ENDDECLS

#endif
