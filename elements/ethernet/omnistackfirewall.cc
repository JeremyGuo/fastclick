/*
 * ethermirror.{cc,hh} -- rewrites Ethernet packet a->b to b->a
 * Eddie Kohler
 *
 * Computational batching support
 * by Georgios Katsikas
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2017 KTH Royal Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/error.hh>
#include "omnistackfirewall.hh"
#include <clicknet/ether.h>
#include <arpa/inet.h>
CLICK_DECLS

OmniStackFireWall::OmniStackFireWall()
{
}

OmniStackFireWall::~OmniStackFireWall()
{
}

static inline 
bool IsMatch(Packet* p, FireWallItem rules[], int rule_size) {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t l2_proto = 0;
    uint8_t l3_proto = 0;

    for (int i = 0; i < rule_size; i ++) {
        auto& rule = rules[i];

        auto ethh = (click_ether*)p->data();
        l2_proto = ethh->ether_type;

        bool matched = false;
        if (!rule.l2_proto_count) {
            matched = true;
        } else {
            for (int j = 0; j < rule.l2_proto_count; j ++) {
                if (rule.l2_proto[j] == l2_proto) {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) continue;

        switch (l2_proto) {
            case ETHERTYPE_IP: {
                auto iph = (click_ip*)(ethh + 1);
                src_ip = iph->ip_src.s_addr;
                dst_ip = iph->ip_dst.s_addr;
                l3_proto = iph->ip_p;

                matched = false;
                if (!rule.l3_proto_count) {
                    matched = true;
                } else {
                    for (int j = 0; j < rule.l3_proto_count; j ++) {
                        if (rule.l3_proto[j] == l3_proto) {
                            matched = true;
                            break;
                        }
                    }
                }
                if (!matched) break;

                switch (l3_proto) {
                    case IPPROTO_TCP: {
                        auto tcph = (click_tcp*)(iph + 1);
                        src_port = tcph->th_sport;
                        dst_port = tcph->th_dport;
                        break;
                    }
                    case IPPROTO_UDP: {
                        auto udph = (click_udp*)(iph + 1);
                        src_port = udph->uh_sport;
                        dst_port = udph->uh_dport;
                        break;
                    }
                    default:
                        return false;
                }
            
                if ((rule.src_ipv4 & rule.src_cidr_mask) == (src_ip & rule.src_cidr_mask) &&
                    (rule.dst_ipv4 & rule.dst_cidr_mask) == (dst_ip & rule.dst_cidr_mask) &&
                    (rule.src_port == UINT32_MAX || rule.src_port == src_port) &&
                    (rule.dst_port == UINT32_MAX || rule.dst_port == dst_port)) {
                    return true;
                }

                break;
            }
            case ETHERTYPE_ARP: {
                break;
            }
        }
    }
    return false;
}

void FireWallItem::Init() {
    src_ipv4 = 0;
    dst_ipv4 = 0;
    src_cidr = 0;
    dst_cidr = 0;
    src_cidr_mask = 0;
    dst_cidr_mask = 0;
    src_port = UINT32_MAX;
    dst_port = UINT32_MAX;
    nic = 0;
    l2_proto = nullptr;
    l3_proto = nullptr;
    l2_proto_count = 0;
    l3_proto_count = 0;
}

int OmniStackFireWall::configure(Vector<String> &conf, ErrorHandler *errh) {
    white_list_size_ = 0;
    black_list_size_ = 0;
    FireWallItem* current_rule = nullptr;
    use_white_list_ = false;

    for (auto& rule_item : conf) {
        if (rule_item == "DEFAULT_WHITE") {
            use_white_list_ = true;
            continue;
        }
        if (rule_item == "BLACK") {
            current_rule = black_list_ + black_list_size_ ++;
            current_rule->Init();
            continue;
        }
        if (rule_item == "WHITE") {
            current_rule = white_list_ + white_list_size_ ++;
            current_rule->Init();
            continue;
        }

        if (rule_item.starts_with("SRC_ADDR:")) {
            auto addr_str = rule_item.substring(9, rule_item.length() - 9);
            inet_aton(addr_str.c_str(), (in_addr*)&current_rule->src_ipv4);
        } else if (rule_item.starts_with("DST_ADDR:")) {
            auto addr_str = rule_item.substring(9, rule_item.length() - 9);
            inet_aton(addr_str.c_str(), (in_addr*)&current_rule->dst_ipv4);
        } else if (rule_item.starts_with("SRC_CIDR:")) {
            auto port_str = rule_item.substring(9, rule_item.length() - 9);
            current_rule->src_cidr = atoi(port_str.c_str());
            current_rule->src_cidr_mask = 0xFFFFFFFF << (32 - current_rule->src_cidr);
        } else if (rule_item.starts_with("DST_CIDR:")) {
            auto port_str = rule_item.substring(9, rule_item.length() - 9);
            current_rule->dst_cidr = atoi(port_str.c_str());
            current_rule->dst_cidr_mask = 0xFFFFFFFF << (32 - current_rule->dst_cidr);
        } else if (rule_item.starts_with("SRC_PORT:")) {
            auto port_str = rule_item.substring(9, rule_item.length() - 9);
            current_rule->src_port = htons(atoi(port_str.c_str()));
        } else if (rule_item.starts_with("DST_PORT:")) {
            auto port_str = rule_item.substring(9, rule_item.length() - 9);
            current_rule->dst_port = htons(atoi(port_str.c_str()));
        } else if (rule_item.starts_with("L2_PROTO:")) {
            auto protos = rule_item.substring(9, rule_item.length() - 9);
            auto proto_list = protos.split(',');
            current_rule->l2_proto_count = proto_list.size();
            current_rule->l2_proto = new uint16_t[current_rule->l2_proto_count];
            for (int i = 0; i < current_rule->l2_proto_count; i ++) {
                if (proto_list[i] == "IPV4")
                    current_rule->l2_proto[i] = htons(ETHERTYPE_IP);
                if (proto_list[i] == "ARP")
                    current_rule->l2_proto[i] = htons(ETHERTYPE_ARP);
            }
        } else if (rule_item.starts_with("L3_PROTO:")) {
            auto protos = rule_item.substring(9, rule_item.length() - 9);
            auto proto_list = protos.split(',');
            current_rule->l3_proto_count = proto_list.size();
            current_rule->l3_proto = new uint8_t[current_rule->l3_proto_count];
            for (int i = 0; i < current_rule->l3_proto_count; i ++) {
                if (proto_list[i] == "TCP")
                    current_rule->l3_proto[i] = IPPROTO_TCP;
                if (proto_list[i] == "UDP")
                    current_rule->l3_proto[i] = IPPROTO_UDP;
                if (proto_list[i] == "ICMP")
                    current_rule->l3_proto[i] = IPPROTO_ICMP;
            }
        } else {
            errh->error("Unknown rule item: %s", rule_item.c_str());
            return -1;
        }
    }

    return 0;
}

Packet *
OmniStackFireWall::simple_action(Packet *p)
{
    if (WritablePacket *q = p->uniqueify()) {
        if (use_white_list_) {
            if (IsMatch(p, white_list_, white_list_size_)) {
                return q;
            } else {
                p->kill();
                return nullptr;
            }
        } else {
            if (IsMatch(p, black_list_, black_list_size_)) {
                p->kill();
                return nullptr;
            } else {
                return q;
            }
        }
        

        return q;
    }

    return 0;
}

#if HAVE_BATCH
PacketBatch *
OmniStackFireWall::simple_action_batch(PacketBatch *batch)
{
#ifdef CLICK_NOINDIRECT
    FOR_EACH_PACKET(batch, p)   {
        OmniStackFireWall::simple_action(p);
    }
#else
    EXECUTE_FOR_EACH_PACKET_DROPPABLE(OmniStackFireWall::simple_action, batch, [](Packet*){});
#endif
    return batch;
}
#endif

CLICK_ENDDECLS
EXPORT_ELEMENT(OmniStackFireWall)
