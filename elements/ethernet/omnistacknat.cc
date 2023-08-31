#include <click/config.h>
#include "omnistacknat.hh"
#include <clicknet/ether.h>
#include <queue>
#include <arpa/inet.h>
#include <click/error.hh>

CLICK_DECLS

OmniStackNAT::OmniStackNAT() {

}

OmniStackNAT::~OmniStackNAT() {

}

int OmniStackNAT::configure(Vector<String> &conf, ErrorHandler *errh) {
    nat_map_ = new HashMap<uint16_t, void*>();
    nat_pool_ = new MemoryPool<OSNATItem>();

    for (auto& item : conf) { // IP:PORT:OUT_PORT
        auto words = item.split(':');
        if (words.size() != 3)
            return errh->error("invalid format");
        OSNATItem* nat_item = nat_pool_->getMemory();
        nat_item->new_port = htons(atoi(words[0].c_str()));
        inet_aton(words[1].c_str(), (in_addr*)&(nat_item->ipv4));
        nat_item->ori_port = htons(atoi(words[2].c_str()));
        nat_map_->insert(nat_item->new_port, (void*)nat_item);
    }

    return 0;
}

Packet* OmniStackNAT::simple_action(Packet* packet) {
    auto ether = (struct click_ether*)(packet->data());
    if (ntohs(ether->ether_type) != ETHERTYPE_IP)
        return packet;
    auto iph = (struct click_ip*)(ether + 1);
    if (iph->ip_p != IPPROTO_TCP && iph->ip_p != IPPROTO_UDP)
        return packet;
    auto tcph = (struct click_tcp*)(iph + 1);
    auto nat_item = (OSNATItem*)nat_map_->find(tcph->th_dport);
    if (nat_item == nullptr)
        return packet;
    tcph->th_dport = nat_item->ori_port;
    iph->ip_dst.s_addr = nat_item->ipv4;
    return packet;
}

#if HAVE_BATCH
PacketBatch*
OmniStackNAT::simple_action_batch(PacketBatch* batch) {
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(OmniStackNAT::simple_action, batch, [](Packet*){});
    return batch;
}
#endif

CLICK_ENDDECLS
EXPORT_ELEMENT(OmniStackNAT)
