#include <click/config.h>
#include "omnistackids.hh"
#include <clicknet/ether.h>
#include <queue>

CLICK_DECLS

OmniStackIDS::OmniStackIDS() {

}

OmniStackIDS::~OmniStackIDS() {

}

void OmniStackIDS::AddPatternString(const String& str) {
    auto current_node = root;
    for (int i = 0; i < str.length(); i ++) {
        auto byte = str[i];
        if (current_node->son[byte] == nullptr)
            current_node->son[byte] = new ACANode();
        current_node = current_node->son[byte];
    }
    current_node->count ++;
}

int OmniStackIDS::configure(Vector<String> &conf, ErrorHandler *errh) {
    root = new ACANode();
    for (auto str : conf)
        AddPatternString(str);
    
    std::queue<ACANode*> que;
    for (int i = 0; i < 256; i ++) {
        if (root->son[i] != nullptr) {
            root->son[i]->fail = root;
            que.push(root->son[i]);
        } else
            root->son[i] = root;
    }
    while (!que.empty()) {
        auto current_node = que.front();
        que.pop();
        for (int i = 0; i < 256; i ++) {
            if (current_node->son[i] != nullptr) {
                current_node->son[i]->fail = current_node->fail->son[i];
                que.push(current_node->son[i]);
            } else {
                current_node->son[i] = current_node->fail->son[i];
            }
        }
    }
    return 0;
}

Packet* OmniStackIDS::simple_action(Packet* packet) {
    auto current_node = root;
    for (int i = 0; i < packet->length(); i ++) {
        auto byte = packet->data()[i];
        current_node = current_node->son[byte];
        if (current_node->count) {
            packet->kill();
            return nullptr;
        }
    }
    return packet;
}

#if HAVE_BATCH
PacketBatch*
OmniStackIDS::simple_action_batch(PacketBatch* batch) {
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(OmniStackIDS::simple_action, batch, [](Packet*){});
    return batch;
}
#endif

CLICK_ENDDECLS
EXPORT_ELEMENT(OmniStackIDS)
