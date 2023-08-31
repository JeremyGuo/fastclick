#include "omnistackids.hh"

CLICK_DECLS

OmniStackIDS::OmniStackIDS() {

}

OmniStackIDS::~OmniStackIDS() {

}

// int OmniStackIDS::configure(Vector<String> &conf, ErrorHandler *errh) {

// }

Packet* OmniStackIDS::simple_action(Packet* packet) {
    return packet;
}

#if HAVE_BATCH
PacketBatch*
OmniStackIDS::simple_action_batch(PacketBatch* batch) {
#ifdef CLICK_NOINDIRECT
    FOR_EACH_PACKET(batch, p)   {
        OmniStackIDS::simple_action(p);
    }
#else
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(PacketBatch::simple_action, batch, [](Packet*){});
#endif
    return batch;
}
#endif

CLICK_ENDDECLS
EXPORT_ELEMENT(OmniStackIDS)
