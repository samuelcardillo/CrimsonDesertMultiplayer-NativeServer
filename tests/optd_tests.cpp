// Unit tests for option D (docs/OPCION-D-EMULADOR.md): everything that does
// not touch the game. Same style as tests.cpp: no framework, each CHECK prints
// the failing line and the run exits non-zero.

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "common/capture_file.h"
#include "common/protocol.h"
#include "common/reliable.h"
#include "common/save_guard.h"
#include "common/send_gate.h"
#include "common/client_session.h"
#include "common/lz_block.h"
#include "common/tick_profile.h"
#include "common/troc_frame.h"
#include "common/troc_link.h"
#include "common/troc_script.h"

using namespace cdmp;

namespace {

int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            ++g_failures;                                                 \
        }                                                                 \
    } while (0)

using Bytes = std::vector<uint8_t>;

Bytes packet(uint16_t op, size_t payload_len, uint8_t fill = 0xAB, int8_t slot = -1) {
    Bytes payload(payload_len, fill);
    return troc::make(op, slot, payload);
}

// ---------------------------------------------------------------- P7

void test_troc_packet() {
    const Bytes payload = {1, 2, 3};
    const Bytes p = troc::make(2490, -1, payload);
    CHECK(p.size() == 8);
    CHECK(p[0] == 0xBA && p[1] == 0x09 && p[2] == 0xFF && p[3] == 3 && p[4] == 0);
    auto v = troc::parse(p);
    CHECK(v && v->opcode == 2490 && v->slot == -1 && v->payload.size() == 3 && v->payload[2] == 3);

    // Header only (empty payload) is a valid packet.
    CHECK(troc::parse(troc::make(2445, 0, {})).has_value());
    // payload_len must match exactly, as in the game.
    Bytes bad = p;
    bad[3] = 4;
    CHECK(!troc::parse(bad));
    bad = p;
    bad.push_back(0);
    CHECK(!troc::parse(bad));
    CHECK(!troc::parse(Bytes{1, 2, 3, 4}));
    // Larger than the game's buffers.
    Bytes huge(troc::kMaxPacketSize + 1, 0);
    CHECK(!troc::parse(huge));
}

void test_troc_batch() {
    troc::Batch b{troc::Dir::ToGuestClient, {packet(2005, 30000), packet(2188, 20), packet(2445, 0)}};
    const Bytes enc = troc::encode_batch(b);
    CHECK(enc.size() == 3 + (2 + 30005) + (2 + 25) + (2 + 5));
    auto d = troc::decode_batch(enc);
    CHECK(d && d->dir == troc::Dir::ToGuestClient && d->packets == b.packets);

    // Empty batch round-trips.
    auto e = troc::decode_batch(troc::encode_batch({troc::Dir::ToHostServer, {}}));
    CHECK(e && e->packets.empty());

    // Malformed: unknown direction, truncation, trailing byte, broken packet.
    Bytes x = enc;
    x[0] = 3;
    CHECK(!troc::decode_batch(x));
    x = enc;
    x.pop_back();
    CHECK(!troc::decode_batch(x));
    x = enc;
    x.push_back(0);
    CHECK(!troc::decode_batch(x));
    x = enc;
    x[3 + 2 + 3] ^= 1;  // payload_len of the first packet
    CHECK(!troc::decode_batch(x));
    CHECK(!troc::decode_batch(Bytes{1, 0}));
}

// C4: the few internal session messages (3-byte header, no length) the
// tunnel carries, exactly as the game builds them, and nothing else.
void test_troc_internal() {
    using troc::Dir;
    const Bytes bye = troc::make_logout_session_req();
    CHECK((bye == Bytes{0xD1, 0x07, 0xFF}));
    CHECK(!troc::parse(bye));  // no u16 length: the ordinary parser refuses it
    auto v = troc::parse_wire(bye, Dir::ToHostServer);
    CHECK(v && v->opcode == 2001 && v->slot == -1 && v->payload.empty());
    CHECK(!troc::parse_wire(bye, Dir::ToGuestClient));   // a Req never goes to the guest
    CHECK(!troc::parse_wire(Bytes{0xD1, 0x07, 0x00}, Dir::ToHostServer));  // slot must be -1
    CHECK(!troc::parse_wire(Bytes{0xD1, 0x07, 0xFF, 0x00}, Dir::ToHostServer));  // exactly 3 bytes
    // A 2001 in the ordinary form (5-byte header) is refused: only the internal form exists.
    CHECK(!troc::parse_wire(troc::make(2001, -1, {}), Dir::ToHostServer));

    const Bytes ack_session = {0xD2, 0x07, 0xFF, 0x04, 0x00, 0x00, 0x00};  // capture 105149
    const Bytes ack_user = {0xD3, 0x07, 0xFF, 0x04, 0x00, 0x00, 0x00};
    auto a = troc::parse_wire(ack_session, Dir::ToGuestClient);
    CHECK(a && a->opcode == 2002 && a->payload.size() == 4 && a->payload[0] == 4);
    CHECK(troc::parse_wire(ack_user, Dir::ToGuestClient).has_value());
    CHECK(!troc::parse_wire(ack_session, Dir::ToHostServer));  // an Ack never goes to the server
    CHECK(!troc::parse_wire(Bytes{0xD2, 0x07, 0xFF, 0x04, 0x00, 0x00}, Dir::ToGuestClient));  // 6 bytes
    // No other internal message passes in the internal form: the shutdown timer
    // 2038 (3 bytes) or 2004 (19 bytes, pointers). (The global shutdown 2790,
    // E6 0A FF 00 00, is a well-formed ordinary packet: the server end refuses
    // it because it is no server Req, server.cpp load_channels.)
    CHECK(!troc::parse_wire(Bytes{0xF6, 0x07, 0xFF}, Dir::ToHostServer));  // 2038, 3 bytes
    CHECK(!troc::parse_wire(Bytes(19, 0xFF), Dir::ToHostServer));
    // Ordinary packets are unchanged.
    CHECK(troc::parse_wire(packet(2490, 19), Dir::ToHostServer).has_value());

    // Through batches and the sender, each in its own direction.
    troc::Batch up{Dir::ToHostServer, {packet(2223, 20), bye}};
    auto d = troc::decode_batch(troc::encode_batch(up));
    CHECK(d && d->packets == up.packets);
    troc::Batch down{Dir::ToGuestClient, {ack_user, ack_session, packet(2516, 9)}};
    auto e = troc::decode_batch(troc::encode_batch(down));
    CHECK(e && e->packets == down.packets);
    troc::Batch wrong{Dir::ToGuestClient, {bye}};
    CHECK(!troc::decode_batch(troc::encode_batch(wrong)));
    std::vector<Bytes> sent;
    troc::TunnelSender s(Dir::ToHostServer, [&](const Bytes& m) {
        sent.push_back(m);
        return true;
    });
    CHECK(s.push(bye) && !s.push(ack_session) && s.refused() == 1);
    troc::TunnelSender g(Dir::ToGuestClient, [&](const Bytes& m) {
        sent.push_back(m);
        return true;
    });
    CHECK(g.push(ack_session) && g.push(ack_user) && !g.push(bye));
}

void test_packet_queue() {
    // Retirar y compactar sin reinsertar: se conserva orden, presupuesto y no se cuentan pérdidas.
    troc::PacketQueue filtered(20);
    CHECK(filtered.push(std::vector<uint8_t>{1, 2, 3}));
    CHECK(filtered.push(std::vector<uint8_t>{9, 8, 7}));
    CHECK(filtered.push(std::vector<uint8_t>{4, 5, 6}));
    filtered.filter_in_place([](auto& packet) noexcept {
        if (packet[0] == 9) return false;
        packet.resize(2);
        return true;
    });
    CHECK(filtered.bytes() == 4 && filtered.dropped() == 0);
    auto preserved = filtered.take_all();
    CHECK(preserved.size() == 2 && preserved[0] == std::vector<uint8_t>({1, 2}) &&
          preserved[1] == std::vector<uint8_t>({4, 5}));

    troc::PacketQueue q(100);
    CHECK(q.push(packet(1, 40)));
    CHECK(q.push(packet(2, 40)));
    CHECK(!q.push(packet(3, 40)));  // 135 > 100
    CHECK(q.dropped() == 1 && q.bytes() == 90);
    auto all = q.take_all();
    CHECK(all.size() == 2 && troc::parse(all[0])->opcode == 1 && troc::parse(all[1])->opcode == 2);
    CHECK(q.bytes() == 0 && q.take_all().empty());

    // Producers on other threads (the game's) and one consumer: nothing lost
    // or reordered per producer.
    troc::PacketQueue big(64 << 20);
    constexpr int kPerThread = 5000;
    std::vector<std::thread> producers;
    for (uint8_t t = 0; t < 4; ++t) {
        producers.emplace_back([&big, t] {
            for (int i = 0; i < kPerThread; ++i) {
                Bytes p = troc::make(static_cast<uint16_t>(i), static_cast<int8_t>(t), Bytes(4, t));
                big.push(p);
            }
        });
    }
    std::vector<int> next(4, 0);
    int got = 0;
    bool ordered = true;
    while (got < 4 * kPerThread) {
        for (auto& p : big.take_all()) {
            auto v = troc::parse(p);
            const auto t = static_cast<size_t>(v->slot);
            if (v->opcode != next[t]) ordered = false;
            next[t] = v->opcode + 1;
            ++got;
        }
        std::this_thread::yield();
    }
    for (auto& th : producers) th.join();
    CHECK(ordered && got == 4 * kPerThread && big.dropped() == 0);
}

void test_tunnel_sender_batching() {
    std::vector<Bytes> sent;
    bool accept = true;
    troc::TunnelSender s(troc::Dir::ToHostServer, [&](const Bytes& m) {
        if (!accept) return false;
        sent.push_back(m);
        return true;
    });
    CHECK(!s.push(Bytes{1, 2, 3}));  // not a packet
    CHECK(s.refused() == 1);
    for (int i = 0; i < 10; ++i) CHECK(s.push(packet(static_cast<uint16_t>(100 + i), 20000)));
    CHECK(s.flush() == 4);  // 3 + 3 + 3 + 1 packets of ~20 KB in 64 KB batches
    CHECK(sent.size() == 4 && s.packets_sent() == 10 && s.backlog_bytes() == 0);
    for (const auto& m : sent) CHECK(m.size() <= troc::TunnelSender::kMaxBatchBytes);

    // The channel refuses: the batch is kept and retried, order intact.
    sent.clear();
    accept = false;
    for (int i = 0; i < 3; ++i) CHECK(s.push(packet(static_cast<uint16_t>(200 + i), 10)));
    CHECK(s.flush() == 0 && sent.empty());
    CHECK(s.push(packet(203, 10)));
    accept = true;
    CHECK(s.flush() == 2);  // the refused batch first, then the new packet
    troc::TunnelReceiver r(troc::Dir::ToHostServer);
    std::vector<uint16_t> ops;
    for (const auto& m : sent) {
        for (const auto& p : r.on_message(m)) ops.push_back(troc::parse(p)->opcode);
    }
    CHECK((ops == std::vector<uint16_t>{200, 201, 202, 203}));

    // Wrong direction is rejected.
    troc::TunnelReceiver wrong(troc::Dir::ToGuestClient);
    CHECK(wrong.on_message(sent[0]).empty() && wrong.rejected() == 1);

    // A stalled link fills the backlog: refused, never unbounded.
    accept = false;
    size_t pushed = 0;
    while (s.push(packet(1, 30000))) ++pushed;
    CHECK(pushed > 0 && s.backlog_bytes() <= troc::TunnelSender::kMaxBacklogBytes);
}

// End to end over two reliable channels with a lossy, reordering link: a
// login-sized burst (big ActorLoadDataAck and many small Acks) arrives whole
// and in order.
void test_tunnel_over_reliable() {
    std::mt19937 rng(1234);
    std::vector<proto::Body> a_to_b, b_to_a;
    ReliableChannel a([&](proto::Body body) { a_to_b.push_back(std::move(body)); });
    ReliableChannel b([&](proto::Body body) { b_to_a.push_back(std::move(body)); });
    uint32_t now = 0;
    troc::TunnelSender sender(troc::Dir::ToGuestClient, [&](const Bytes& m) {
        return a.unacked_fragments() < 1500 && a.send(proto::RelKind::TrocFrame, m, now);
    });
    troc::TunnelReceiver receiver(troc::Dir::ToGuestClient);

    std::vector<Bytes> expected;
    for (int i = 0; i < 400; ++i) {
        const size_t len = (i % 25 == 0) ? 28000 : static_cast<size_t>(rng() % 600);
        // 3000+: clear of 2001-2003, which only exist in their internal form (C4)
        Bytes p = packet(static_cast<uint16_t>(3000 + i % 900), len, static_cast<uint8_t>(i));
        expected.push_back(p);
        CHECK(sender.push(p));
    }
    std::vector<Bytes> got;
    for (int step = 0; step < 4000 && got.size() < expected.size(); ++step) {
        now += 10;
        sender.flush();
        a.tick(now);
        std::shuffle(a_to_b.begin(), a_to_b.end(), rng);
        for (auto& body : a_to_b) {
            if (rng() % 100 < 15) continue;  // 15 % loss
            auto& d = std::get<proto::RelData>(body);
            for (auto& msg : b.on_data(d)) {
                CHECK(msg.kind == proto::RelKind::TrocFrame);
                for (auto& p : receiver.on_message(msg.bytes)) got.push_back(std::move(p));
            }
        }
        a_to_b.clear();
        for (auto& body : b_to_a) {
            if (rng() % 100 < 15) continue;
            a.on_ack(std::get<proto::RelAck>(body));
        }
        b_to_a.clear();
    }
    CHECK(got == expected);
    CHECK(receiver.rejected() == 0);
}

// Two ClientSessions wired back to back in memory: the guest (cdmp_peer's
// replay, Initiator) and the host's mod (Responder), each with its TrocLink.
void test_troc_link() {
    std::vector<Bytes> to_host, to_guest;
    ClientSession guest("guest", 0, [&](const Bytes& b) { to_host.push_back(b); }, {},
                        ClientSession::Role::Initiator);
    ClientSession host("host", 0, [&](const Bytes& b) { to_guest.push_back(b); }, {},
                       ClientSession::Role::Responder);
    std::vector<Bytes> host_got, guest_got;
    troc::TrocLink guest_link(guest, troc::Dir::ToHostServer, troc::Dir::ToGuestClient,
                              [&](Bytes&& p, uint32_t) { guest_got.push_back(std::move(p)); });
    troc::TrocLink host_link(host, troc::Dir::ToGuestClient, troc::Dir::ToHostServer,
                             [&](Bytes&& p, uint32_t) { host_got.push_back(std::move(p)); });
    uint32_t now = 1000;
    auto pump = [&](int rounds) {
        for (int i = 0; i < rounds; ++i) {
            now += 5;
            guest.tick(now);
            host.tick(now);
            guest_link.tick(now);
            host_link.tick(now);
            auto a = std::move(to_host);
            to_host.clear();
            for (auto& b : a) host.on_datagram(b, now);
            auto c = std::move(to_guest);
            to_guest.clear();
            for (auto& b : c) guest.on_datagram(b, now);
        }
    };
    pump(5);
    CHECK(guest.state() == ClientSession::State::Connected && host.state() == ClientSession::State::Connected);
    CHECK(!guest_link.broken() && !host_link.broken());

    // The guest's login Req reach the host; the server's burst reaches the guest.
    CHECK(guest_link.push(packet(2319, 286)));
    CHECK(guest_link.push(packet(2490, 14)));
    for (int i = 0; i < 300; ++i) CHECK(host_link.push(packet(static_cast<uint16_t>(2005 + i % 3), i % 10 ? 200 : 20000)));
    pump(200);
    CHECK(host_got.size() == 2 && troc::parse(host_got[0])->opcode == 2319 && troc::parse(host_got[1])->opcode == 2490);
    CHECK(guest_got.size() == 300 && troc::parse(guest_got[299])->opcode == 2005 + 299 % 3);
    CHECK(!guest_link.push(Bytes{1, 2}) && guest_link.broken());  // not a packet: broken
    guest_link.reset();
    CHECK(!guest_link.broken());

    // The host restarts its side: a new connection breaks both tunnels.
    host.disconnect(now);
    pump(400);
    CHECK(guest.state() == ClientSession::State::Connected && host.state() == ClientSession::State::Connected);
    CHECK(host_link.broken() && guest_link.broken());
    CHECK(!host_link.push(packet(1, 1)));
    host_link.reset();
    guest_link.reset();
    CHECK(host_link.push(packet(2716, 0)));
    pump(20);
    CHECK(guest_got.size() == 301);
}

// Native payloads may cross the tunnel only after both endpoints identify
// the same executable and opcode map. Reconnection and reset cannot erase a
// mismatch on the current connection.
void test_troc_link_identity() {
    for (int scenario = 0; scenario < 5; ++scenario) {
        std::vector<Bytes> to_host, to_guest, host_got, guest_got;
        ClientSession guest("guest", 0, [&](const Bytes& b) { to_host.push_back(b); }, {},
                            ClientSession::Role::Initiator);
        ClientSession host("host", 0, [&](const Bytes& b) { to_guest.push_back(b); }, {},
                           ClientSession::Role::Responder);
        troc::TrocLink guest_link(guest, troc::Dir::ToHostServer, troc::Dir::ToGuestClient,
            [&](Bytes&& p, uint32_t) { guest_got.push_back(std::move(p)); });
        troc::TrocLink host_link(host, troc::Dir::ToGuestClient, troc::Dir::ToHostServer,
            [&](Bytes&& p, uint32_t) { host_got.push_back(std::move(p)); });
        host_link.require_identity(3527, 0x123456789ABCDEF0ULL);
        if (scenario < 3)
            guest_link.require_identity(scenario == 1 ? 2976 : 3527,
                scenario == 2 ? 0x123456789ABCDEF1ULL : 0x123456789ABCDEF0ULL);
        uint32_t now = 1000;
        auto pump = [&](int rounds) {
            for (int i = 0; i < rounds; ++i) {
                now += 5;
                guest.tick(now); host.tick(now);
                guest_link.tick(now); host_link.tick(now);
                auto a = std::move(to_host); to_host.clear();
                for (auto& b : a) host.on_datagram(b, now);
                auto b = std::move(to_guest); to_guest.clear();
                for (auto& p : b) guest.on_datagram(p, now);
            }
        };
        CHECK(!host_link.connected());
        pump(30);
        CHECK(host.state() == ClientSession::State::Connected);
        if (scenario >= 3) {
            // A peer bypassing the identity handshake cannot reach native code.
            // Opcode 3 is reserved; malformed identities fail just like game data.
            CHECK(guest.send_reliable(proto::RelKind::TrocFrame,
                troc::encode_batch({troc::Dir::ToHostServer, {packet(scenario == 3 ? 2319 : 3, 1)}}), now));
            pump(30);
        }
        if (scenario == 0) {
            CHECK(host_link.connected() && guest_link.connected());
            CHECK(!host_link.broken() && !guest_link.broken());
            CHECK(host_got.empty() && guest_got.empty());  // identities never reach game code
            CHECK(guest_link.push(packet(2319, 4)));
            CHECK(host_link.push(packet(2005, 4)));
            pump(30);
            CHECK(host_got.size() == 1 && guest_got.size() == 1);
            host.disconnect(now);
            pump(400);
            CHECK(host_link.broken() && guest_link.broken());
            host_link.reset(); guest_link.reset();
            CHECK(!host_link.connected() && !guest_link.connected());
            pump(30);
            CHECK(host_link.connected() && guest_link.connected());
        } else {
            CHECK(host_link.broken());
            CHECK(!host_link.connected());
            CHECK(host_got.empty());
            host_link.reset();
            CHECK(host_link.broken());
            CHECK(!host_link.push(packet(2005, 4)));
        }
    }
}

void test_troc_link_identity_lifecycle() {
    for (const bool late_guest : {false, true}) {
        std::vector<Bytes> to_host, to_guest;
        ClientSession guest("guest", 0, [&](const Bytes& b) { to_host.push_back(b); }, {},
                            ClientSession::Role::Initiator);
        ClientSession host("host", 0, [&](const Bytes& b) { to_guest.push_back(b); }, {},
                           ClientSession::Role::Responder);
        troc::TrocLink host_link(host, troc::Dir::ToGuestClient, troc::Dir::ToHostServer, [](Bytes&&, uint32_t) {});
        host_link.require_identity(3527, 42);
        std::unique_ptr<troc::TrocLink> guest_link;
        auto attach_guest = [&] {
            guest_link = std::make_unique<troc::TrocLink>(guest, troc::Dir::ToHostServer, troc::Dir::ToGuestClient,
                                                         [](Bytes&&, uint32_t) {});
            guest_link->require_identity(3527, 42);
        };
        if (!late_guest) attach_guest();
        uint32_t now = 1000;
        auto pump = [&](int rounds, bool tick_guest = true) {
            for (int i = 0; i < rounds; ++i) {
                now += 5;
                guest.tick(now); host.tick(now);
                // Match mod.cpp: drain Welcome and reliable packets before the
                // link observes the connection in tick().
                auto a = std::move(to_host); to_host.clear();
                for (auto& b : a) host.on_datagram(b, now);
                auto b = std::move(to_guest); to_guest.clear();
                for (auto& p : b) guest.on_datagram(p, now);
                host_link.tick(now);
                if (guest_link && tick_guest) guest_link->tick(now);
            }
        };
        pump(150);
        if (late_guest) {
            CHECK(!host_link.connected() && !host_link.broken());
            CHECK(host_link.packets_out() > 0);  // first identity ACKed without a receiver
            attach_guest();
            // Only host retries advance: a late handler receives its declaration
            // even if the guest hasn't begun its network-loop tick yet.
            pump(400, false);
            CHECK(guest_link->connected() && !guest_link->broken());
            pump(20);
        }
        CHECK(host_link.connected() && guest_link->connected());
        CHECK(!host_link.broken() && !guest_link->broken());
        pump(30);
        const uint64_t sent = host_link.packets_out() + guest_link->packets_out();
        pump(500);
        CHECK(host_link.packets_out() + guest_link->packets_out() == sent);  // no response ping-pong
    }
}

// The guest's game dies without a goodbye and a new process connects to the same host. The new connection breaks the
// host's link, the broken link drops the new guest's identity, and only a reset lets it through (2026-11-05, two PCs).
void test_troc_link_guest_crash_and_return() {
    std::vector<Bytes> to_host, to_guest;
    auto guest = std::make_unique<ClientSession>("guest", 0, [&](const Bytes& b) { to_host.push_back(b); },
                                                 ClientSession::EventFn{}, ClientSession::Role::Initiator);
    ClientSession host("host", 0, [&](const Bytes& b) { to_guest.push_back(b); }, {}, ClientSession::Role::Responder);
    std::vector<Bytes> host_got;
    troc::TrocLink host_link(host, troc::Dir::ToGuestClient, troc::Dir::ToHostServer,
                             [&](Bytes&& p, uint32_t) { host_got.push_back(std::move(p)); });
    host_link.require_identity(3527, 42);
    auto make_guest_link = [&] {
        auto link = std::make_unique<troc::TrocLink>(*guest, troc::Dir::ToHostServer, troc::Dir::ToGuestClient,
                                                     [](Bytes&&, uint32_t) {});
        link->require_identity(3527, 42);
        return link;
    };
    auto guest_link = make_guest_link();
    uint32_t now = 1000;
    bool guest_alive = true;
    auto pump = [&](int rounds) {
        for (int i = 0; i < rounds; ++i) {
            now += 5;
            if (guest_alive) guest->tick(now);
            host.tick(now);
            auto a = std::move(to_host);
            to_host.clear();
            for (auto& b : a) host.on_datagram(b, now);
            auto c = std::move(to_guest);
            to_guest.clear();
            if (guest_alive) {
                for (auto& p : c) guest->on_datagram(p, now);
            }
            host_link.tick(now);
            if (guest_alive) guest_link->tick(now);
        }
    };
    pump(150);
    CHECK(host_link.connected() && guest_link->connected());
    CHECK(guest_link->push(packet(2716, 0)));
    pump(20);
    CHECK(host_got.size() == 1);

    // The crash: nothing more from that process, and the host times it out.
    guest_alive = false;
    guest_link.reset();
    guest.reset();
    pump(1400);
    CHECK(host.state() != ClientSession::State::Connected);

    // A new process, on a newer connection. However long it tries, the broken link never lets its identity in.
    const uint32_t old_epoch = host.epoch();
    guest = std::make_unique<ClientSession>("guest", 0, [&](const Bytes& b) { to_host.push_back(b); },
                                            ClientSession::EventFn{}, ClientSession::Role::Initiator);
    guest_link = make_guest_link();
    guest_alive = true;
    pump(2000);
    CHECK(host.state() == ClientSession::State::Connected && host.epoch() > old_epoch);
    CHECK(host_link.broken() && !host_link.connected());
    CHECK(!guest_link->connected());

    // What the host does in READY (GuestLifecycle::link_reset_due): the same connection then works.
    host_link.reset();
    CHECK(!host_link.broken());
    pump(400);
    CHECK(host_link.connected() && guest_link->connected());
    CHECK(!host_link.broken() && !guest_link->broken());
    CHECK(guest_link->push(packet(2716, 0)));
    pump(20);
    CHECK(host_got.size() == 2);
}

// A Steam-like link: a send buffer drained at a fixed rate, then a fixed
// latency. Refuses (LimitExceeded) what does not fit in the buffer. Feeds a
// SendGate the way SteamTransport does: every send, every refusal, and a
// reading of the queue every 20 ms.
struct SimSteamLink {
    uint32_t rate;  // bytes/s
    size_t buffer;
    uint32_t latency_ms;
    net::SendGate gate;
    std::deque<Bytes> queue;
    std::deque<std::pair<uint32_t, Bytes>> wire;
    size_t pending = 0, max_pending = 0;
    uint64_t refused = 0, credit = 0;
    uint32_t last_ms = 0, last_status_ms = 0;

    SimSteamLink(uint32_t r, size_t b, uint32_t lat, uint32_t now)
        : rate(r), buffer(b), latency_ms(lat), gate(net::SendGate::Config{.assumed_rate = r}), last_ms(now),
          last_status_ms(now) {}
    void send(const Bytes& b, uint32_t now) {
        if (pending + b.size() > buffer) {
            ++refused;
            gate.on_refused(now);
            return;
        }
        queue.push_back(b);
        pending += b.size();
        max_pending = std::max(max_pending, pending);
        gate.on_sent(now, b.size());
    }
    void advance(uint32_t now) {
        credit += static_cast<uint64_t>(rate) * (now - last_ms) / 1000;
        last_ms = now;
        while (!queue.empty() && credit >= queue.front().size()) {
            credit -= queue.front().size();
            pending -= queue.front().size();
            wire.emplace_back(now + latency_ms, std::move(queue.front()));
            queue.pop_front();
        }
        if (queue.empty()) credit = 0;  // an idle link banks nothing
        if (now - last_status_ms >= 20) {
            last_status_ms = now;
            gate.on_status(now, pending, rate);
        }
    }
    template <class F>
    void deliver(uint32_t now, F&& f) {
        while (!wire.empty() && wire.front().first <= now) {
            f(wire.front().second);
            wire.pop_front();
        }
    }
};

struct SteamSimResult {
    size_t delivered = 0;
    bool in_order = true;
    bool connected = false, broken = false;
    uint64_t refused = 0, resent = 0, held_back = 0;
    size_t max_pending = 0, limit = 0, fragments = 0;
    uint32_t ms = 0;
};

// The host's tunnel pushes `packets` x 20 KB (a P8 world load) to the guest
// over the simulated link, with the backpressure of the mod's Steam setup
// (gated) or without it.
SteamSimResult run_steam_sim(uint32_t rate, size_t buffer, size_t packets, bool gated = true) {
    uint32_t now = 1000;
    SimSteamLink down(rate, buffer, 30, now), up(rate, buffer, 30, now);
    ClientSession guest("guest", 0, [&](const Bytes& b) { up.send(b, now); }, {}, ClientSession::Role::Initiator);
    ClientSession host("host", 0, [&](const Bytes& b) { down.send(b, now); }, {}, ClientSession::Role::Responder);
    if (gated) {
        host.set_congestion_probe([&] { return down.gate.congested(now); });
        host.set_reliable_window(512);
    }
    SteamSimResult r;
    uint16_t expect = 0;
    troc::TrocLink guest_link(guest, troc::Dir::ToHostServer, troc::Dir::ToGuestClient, [&](Bytes&& p, uint32_t) {
        const auto v = troc::parse(p);
        if (!v || v->opcode != 2005 + expect % 1000) r.in_order = false;
        ++expect;
        ++r.delivered;
    });
    troc::TrocLink host_link(host, troc::Dir::ToGuestClient, troc::Dir::ToHostServer, [](Bytes&&, uint32_t) {});
    auto step = [&] {
        now += 5;
        guest.tick(now);
        host.tick(now);
        guest_link.tick(now);
        host_link.tick(now);
        down.advance(now);
        up.advance(now);
        up.deliver(now, [&](const Bytes& b) { host.on_datagram(b, now); });
        down.deliver(now, [&](const Bytes& b) { guest.on_datagram(b, now); });
    };
    for (int i = 0; i < 400; ++i) step();  // connect, measure the RTT
    for (size_t i = 0; i < packets; ++i) host_link.push(packet(static_cast<uint16_t>(2005 + i % 1000), 20000));
    const uint32_t start = now;
    while (r.delivered < packets && now - start < 120000) step();
    r.ms = now - start;
    r.connected = guest.state() == ClientSession::State::Connected && host.state() == ClientSession::State::Connected;
    r.broken = host_link.broken() || guest_link.broken();
    r.refused = down.refused;
    r.resent = host.reliable_resent();
    r.held_back = host.reliable_held_back();
    r.max_pending = down.max_pending;
    r.limit = down.gate.limit_bytes();
    r.fragments = packets * 20005 / proto::kRelChunk;
    return r;
}

// The first P8 session over Steam: the reliable channel filled Steam's 512 KB
// buffer (LimitExceeded), the queue reached ~2 s and every fragment was resent
// several times. With the gate, Steam's queue stays near its limit (~100 ms of
// data), nothing is refused, almost nothing is resent and the transfer runs
// at the link's rate.
void test_steam_backpressure() {
    // The mod's limits: 1 MB/s, 4 MB buffer. 2 MB of world data.
    auto fast = run_steam_sim(1024 * 1024, 4 * 1024 * 1024, 100);
    CHECK(fast.delivered == 100 && fast.in_order && fast.connected && !fast.broken);
    CHECK(fast.refused == 0);
    CHECK(fast.max_pending < fast.limit + 8 * 1024);
    CHECK(fast.resent * 20 < fast.fragments);
    CHECK(fast.held_back > 0);
    CHECK(fast.ms < 2000 * 3 / 2 + 1000);  // ~2 s at 1 MB/s
    // Steam's defaults: 256 KB/s and a 512 KB buffer, smaller than the
    // window (512 x 1100 B): only the gate keeps it from overflowing.
    auto slow = run_steam_sim(256 * 1024, 512 * 1024, 50);
    CHECK(slow.delivered == 50 && slow.in_order && slow.connected && !slow.broken);
    CHECK(slow.refused == 0);
    CHECK(slow.max_pending < slow.limit + 8 * 1024);
    CHECK(slow.resent * 20 < slow.fragments);
    CHECK(slow.ms < 4000 * 3 / 2 + 1000);  // ~4 s at 256 KB/s
    // The same without the gate (UDP's setup, window 128): Steam's queue
    // grows to ~1.6 s and well over half the fragments are resent.
    auto ungated = run_steam_sim(256 * 1024, 512 * 1024, 50, false);
    CHECK(ungated.delivered == 50 && ungated.in_order);
    CHECK(ungated.max_pending > 4 * slow.max_pending);
    CHECK(ungated.resent > slow.resent + ungated.fragments / 4);
}

// ---------------------------------------------------------------- tunnel performance (p8-tunel-rendimiento.md)

void check_lz_round_trip(const Bytes& in) {
    const Bytes z = lz::compress(in);
    Bytes out;
    CHECK(lz::decompress(z, in.size(), out));
    CHECK(out == in);
    // The size must be exact, both ways.
    if (!in.empty()) CHECK(!lz::decompress(z, in.size() - 1, out));
    CHECK(!lz::decompress(z, in.size() + 1, out));
}

void test_lz_codec() {
    std::mt19937 rng(77);
    check_lz_round_trip({});
    for (size_t n = 1; n < 40; ++n) {
        Bytes b(n);
        for (auto& c : b) c = static_cast<uint8_t>(rng() % 3);
        check_lz_round_trip(b);
    }
    Bytes zeros(100000, 0);
    check_lz_round_trip(zeros);
    CHECK(lz::compress(zeros).size() < 1000);
    Bytes random(100000);
    for (auto& c : random) c = static_cast<uint8_t>(rng());
    check_lz_round_trip(random);
    CHECK(lz::compress(random).size() < random.size() + random.size() / 200 + 16);
    // Repeats at the window's edge and past it, and long literal runs between them.
    for (size_t period : {1u, 3u, 617u, 4096u, 65535u, 65536u, 70000u}) {
        Bytes b(period + 20000);
        for (size_t i = 0; i < period; ++i) b[i] = static_cast<uint8_t>(rng());
        for (size_t i = period; i < b.size(); ++i) b[i] = b[i - period];
        check_lz_round_trip(b);
    }
    Bytes mixed;
    for (int k = 0; k < 50; ++k) {
        const size_t lit = rng() % 900, rep = rng() % 700;
        for (size_t i = 0; i < lit; ++i) mixed.push_back(static_cast<uint8_t>(rng()));
        for (size_t i = 0; i < rep; ++i) mixed.push_back(static_cast<uint8_t>(k));
    }
    check_lz_round_trip(mixed);
    // Malformed input: never a crash, never more than raw_size bytes, and a
    // truncated stream always fails.
    const Bytes z = lz::compress(mixed);
    Bytes out;
    for (size_t cut = 0; cut < z.size(); cut += 7) CHECK(!lz::decompress(std::span(z).first(cut), mixed.size(), out));
    for (int k = 0; k < 2000; ++k) {
        Bytes bad = z;
        bad[rng() % bad.size()] ^= static_cast<uint8_t>(1 + rng() % 255);
        if (lz::decompress(bad, mixed.size(), out)) CHECK(out.size() == mixed.size());
    }
    for (int k = 0; k < 2000; ++k) {
        Bytes junk(rng() % 64);
        for (auto& c : junk) c = static_cast<uint8_t>(rng());
        if (lz::decompress(junk, 1000, out)) CHECK(out.size() == 1000);
    }
    // A match before the start of the output, and an offset of 0.
    CHECK(!lz::decompress(Bytes{0x10, 0xAA, 0x05, 0x00}, 5, out));
    CHECK(!lz::decompress(Bytes{0x10, 0xAA, 0x00, 0x00}, 5, out));
}

// What a field entry's burst looks like (P8 session 6B, guest capture
// cdmp_packets_20261009-224848.bin): SyncSceneObjectAck 2665 of 615 bytes that
// differ in an object id and a few fields, then ActorLoadDataAck 2005.
Bytes scene_object(uint32_t id, std::mt19937& rng) {
    Bytes payload(610, 0);
    payload[4] = 1;
    std::memcpy(payload.data() + 8, &id, 4);
    const uint8_t tail[] = {0xAC, 0x3B, 0xAC, 0x10, 0x50, 0xEB, 0xF6, 0x59, 0x1D, 0xB4};
    std::memcpy(payload.data() + 12, tail, sizeof tail);
    payload[26] = 1;
    payload[33] = 2;
    std::memset(payload.data() + 44, 0xFF, 4);
    for (int i = 0; i < 6; ++i) payload[64 + rng() % 500] = static_cast<uint8_t>(rng());  // a few fields
    return troc::make(2665, -1, payload);
}
Bytes actor_load(uint32_t key, std::mt19937& rng) {
    Bytes payload(6000, 0);
    std::memcpy(payload.data(), &key, 4);
    for (size_t i = 4; i < payload.size(); i += 2) payload[i] = static_cast<uint8_t>(rng());  // half noise
    return troc::make(2005, -1, payload);
}

void test_compressed_batches() {
    std::mt19937 rng(5);
    troc::Batch b{troc::Dir::ToGuestClient, {}};
    for (uint32_t i = 0; i < 80; ++i) b.packets.push_back(scene_object(i, rng));
    b.packets.push_back(troc::make(2144, -1, Bytes(46, 7)));
    const Bytes raw = troc::encode_batch(b);
    const auto z = troc::compress_batch(raw);
    CHECK(z.has_value());
    if (!z) return;
    CHECK(z->size() * 5 < raw.size());
    CHECK((*z)[0] == (static_cast<uint8_t>(troc::Dir::ToGuestClient) | troc::kCompressedFlag));
    auto back = troc::decode_message(*z);
    CHECK(back && back->dir == troc::Dir::ToGuestClient && back->packets == b.packets);
    CHECK(troc::decode_message(raw)->packets == b.packets);  // the raw form still decodes
    // Malformed compressed messages.
    Bytes wrong_dir = *z;
    wrong_dir[0] = static_cast<uint8_t>(troc::Dir::ToHostServer) | troc::kCompressedFlag;
    CHECK(!troc::decode_message(wrong_dir));
    Bytes too_big = *z;
    too_big[4] = 0x7F;  // raw size far above kMaxRawBatchBytes
    CHECK(!troc::decode_message(too_big));
    Bytes wrong_size = *z;
    wrong_size[1] ^= 1;
    CHECK(!troc::decode_message(wrong_size));
    CHECK(!troc::decode_message(std::span(*z).first(z->size() - 1)));
    CHECK(!troc::decode_message(std::span(*z).first(3)));
    // Data that does not compress goes raw.
    Bytes noise(3000);
    for (auto& c : noise) c = static_cast<uint8_t>(rng());
    CHECK(!troc::compress_batch(troc::encode_batch({troc::Dir::ToGuestClient, {troc::make(2005, -1, noise)}})));

    // The sender: same packets, same order, fewer bytes; the receiver takes both forms.
    std::vector<Bytes> sent;
    troc::TunnelSender s(troc::Dir::ToGuestClient, [&](const Bytes& m) {
        sent.push_back(m);
        return true;
    });
    std::vector<Bytes> expected;
    uint64_t raw_part = 0;
    for (uint32_t i = 0; i < 6000; ++i) {
        if (i == 1000) {
            CHECK(s.flush() > 0);  // a raw part first
            CHECK(s.compressed_batches() == 0 && s.wire_bytes_sent() == s.raw_bytes_sent());
            raw_part = s.raw_bytes_sent();
            s.set_compress(true);
        }
        expected.push_back(i % 50 == 49 ? actor_load(i, rng) : scene_object(i, rng));
        CHECK(s.push(expected.back()));
    }
    expected.push_back(troc::make(2144, -1, Bytes(46, 7)));
    CHECK(s.push(expected.back()));
    size_t flushes = 0;
    while (s.flush() > 0 || s.backlog_bytes() > 0) ++flushes;
    CHECK(flushes >= 3);  // ~3.6 MB: kMaxCompressPerFlush spreads the work over several loops
    CHECK(s.compressed_batches() > 0);
    CHECK((s.wire_bytes_sent() - raw_part) * 3 < s.raw_bytes_sent() - raw_part);
    troc::TunnelReceiver r(troc::Dir::ToGuestClient);
    std::vector<Bytes> got;
    for (const auto& m : sent) {
        CHECK(m.size() <= proto::kMaxRelMessage);
        for (auto& p : r.on_message(m)) got.push_back(std::move(p));
    }
    CHECK(got == expected);
    CHECK(r.rejected() == 0 && r.compressed_received() == s.compressed_batches());
}

// The capability handshake over two TrocLinks: the guest says it decodes
// compressed batches; the host compresses only then, and only on that connection.
void test_troc_link_compression() {
    std::vector<Bytes> to_host, to_guest;
    ClientSession guest("guest", 0, [&](const Bytes& b) { to_host.push_back(b); }, {}, ClientSession::Role::Initiator);
    ClientSession host("host", 0, [&](const Bytes& b) { to_guest.push_back(b); }, {}, ClientSession::Role::Responder);
    std::vector<Bytes> host_got, guest_got;
    troc::TrocLink guest_link(guest, troc::Dir::ToHostServer, troc::Dir::ToGuestClient,
                              [&](Bytes&& p, uint32_t) { guest_got.push_back(std::move(p)); });
    troc::TrocLink host_link(host, troc::Dir::ToGuestClient, troc::Dir::ToHostServer,
                             [&](Bytes&& p, uint32_t) { host_got.push_back(std::move(p)); });
    uint32_t now = 1000;
    auto pump = [&](int rounds) {
        for (int i = 0; i < rounds; ++i) {
            now += 5;
            guest.tick(now);
            host.tick(now);
            guest_link.tick(now);
            host_link.tick(now);
            auto a = std::move(to_host);
            to_host.clear();
            for (auto& b : a) host.on_datagram(b, now);
            auto c = std::move(to_guest);
            to_guest.clear();
            for (auto& b : c) guest.on_datagram(b, now);
        }
    };
    host_link.set_compress(true);
    pump(20);
    CHECK(!host_link.peer_decodes_compressed() && !host_link.compressing());  // nobody said anything
    guest_link.set_announce_caps(true);
    pump(20);
    CHECK(!host_link.peer_decodes_compressed());  // the caps go with the guest's first packet, never alone
    CHECK(guest_link.push(packet(2319, 286)));
    pump(20);
    CHECK(host_link.peer_decodes_compressed() && host_link.compressing());
    CHECK(host_got.size() == 1 && troc::parse(host_got[0])->opcode == 2319);  // the caps never reach the owner
    std::mt19937 rng(9);
    std::vector<Bytes> expected;
    for (uint32_t i = 0; i < 500; ++i) {
        expected.push_back(scene_object(i, rng));
        CHECK(host_link.push(expected.back()));
    }
    CHECK(guest_link.push(packet(2549, 1)));
    pump(200);
    CHECK(guest_got == expected);
    CHECK(host_got.size() == 2 && troc::parse(host_got[1])->opcode == 2549);
    CHECK(host_link.wire_bytes_out() * 4 < host_link.raw_bytes_out());
    CHECK(host_link.describe().find("compression ON") != std::string::npos);
    // Without the host's key: raw, whatever the guest says.
    host_link.set_compress(false);
    pump(2);
    CHECK(!host_link.compressing() && host_link.peer_decodes_compressed());
    // A new connection: the caps of the old one no longer count until the guest says them again.
    host_link.set_compress(true);
    host.disconnect(now);
    pump(400);
    CHECK(host_link.broken() && guest_link.broken());
    CHECK(!host_link.peer_decodes_compressed());
    host_link.reset();
    guest_link.reset();
    pump(20);
    CHECK(!host_link.peer_decodes_compressed());
    CHECK(guest_link.push(packet(2319, 286)));
    pump(20);
    CHECK(host_link.peer_decodes_compressed());
    CHECK(host_got.size() == 3 && troc::parse(host_got[2])->opcode == 2319);  // still no caps packet for the owner
    // P8 review M7: opcode 2 is the caps packet only in ToHostServer batches; toward the guest it is the owner's.
    const size_t before = guest_got.size();
    CHECK(host_link.push(packet(troc::kCapsOpcode, 1, 0x01)));
    pump(20);
    CHECK(guest_got.size() == before + 1 && troc::parse(guest_got.back())->opcode == troc::kCapsOpcode);
    CHECK(!guest_link.peer_decodes_compressed());
}

struct BurstResult {
    bool in_order = true, delivered_all = false;
    uint32_t ms_to_2144 = 0;
    size_t burst = 0;
};

// The field entry of P8 session 6B over the simulated Steam link at 1 MB/s:
// the server's burst (2665 x N, 2005s) and then its 2144, in that order.
// Compressed, the 2144 comes out as late as its burst allows, but much sooner.
BurstResult run_burst_sim(bool compress) {
    uint32_t now = 1000;
    SimSteamLink down(1024 * 1024, 4 * 1024 * 1024, 30, now), up(1024 * 1024, 4 * 1024 * 1024, 30, now);
    ClientSession guest("guest", 0, [&](const Bytes& b) { up.send(b, now); }, {}, ClientSession::Role::Initiator);
    ClientSession host("host", 0, [&](const Bytes& b) { down.send(b, now); }, {}, ClientSession::Role::Responder);
    host.set_congestion_probe([&] { return down.gate.congested(now); });
    host.set_reliable_window(512);
    BurstResult r;
    std::vector<Bytes> burst;
    std::mt19937 rng(42);
    for (uint32_t i = 0; i < 4000; ++i) burst.push_back(i % 60 == 59 ? actor_load(i, rng) : scene_object(i, rng));
    r.burst = burst.size();
    size_t next = 0;
    uint32_t start = 0;
    troc::TrocLink guest_link(guest, troc::Dir::ToHostServer, troc::Dir::ToGuestClient, [&](Bytes&& p, uint32_t) {
        const auto v = troc::parse(p);
        if (!v) {
            r.in_order = false;
            return;
        }
        if (v->opcode == 2144) {
            if (next != burst.size()) r.in_order = false;  // the 2144 only after everything before it
            r.delivered_all = next == burst.size();
            r.ms_to_2144 = now - start;
            return;
        }
        if (next >= burst.size() || p != burst[next]) r.in_order = false;
        ++next;
    });
    troc::TrocLink host_link(host, troc::Dir::ToGuestClient, troc::Dir::ToHostServer, [](Bytes&&, uint32_t) {});
    guest_link.set_announce_caps(true);
    host_link.set_compress(compress);
    auto step = [&] {
        now += 5;
        guest.tick(now);
        host.tick(now);
        guest_link.tick(now);
        host_link.tick(now);
        down.advance(now);
        up.advance(now);
        up.deliver(now, [&](const Bytes& b) { host.on_datagram(b, now); });
        down.deliver(now, [&](const Bytes& b) { guest.on_datagram(b, now); });
    };
    for (int i = 0; i < 400; ++i) step();
    guest_link.push(packet(2549, 1));  // the guest's Req (its caps go with it)
    for (int i = 0; i < 100; ++i) step();
    CHECK(host_link.compressing() == compress);
    start = now;
    for (const auto& p : burst) host_link.push(p);
    host_link.push(troc::make(2144, -1, Bytes(46, 7)));
    while (!r.ms_to_2144 && now - start < 60000) step();
    return r;
}

void test_load_burst_latency() {
    const BurstResult raw = run_burst_sim(false);
    const BurstResult z = run_burst_sim(true);
    std::printf("optd: field-entry burst of %zu packets then its 2144 at 1 MB/s: raw %u ms, compressed %u ms\n",
                raw.burst, raw.ms_to_2144, z.ms_to_2144);
    CHECK(raw.in_order && raw.delivered_all && z.in_order && z.delivered_all);
    CHECK(raw.ms_to_2144 > 2000);
    CHECK(z.ms_to_2144 * 3 < raw.ms_to_2144);
}

void test_tick_profile() {
    TickProfile p;
    const char* names[] = {"a", "b", "c"};
    p.begin(1000);
    p.mark(0, 1050);       // a: 50 us
    p.mark(2, 401050);     // c: 400 ms
    p.mark(1, 401250);     // b: 0.2 ms
    p.mark(99, 500000);    // out of range: ignored
    CHECK(p.end(401300, 50'000) == 400300);
    CHECK(p.worst() == 2 && p.part_us(2) == 400000 && p.part_us(1) == 200);
    CHECK(p.text(names) == "400.3 ms: b 0.2 ms, c 400.0 ms");
    p.begin(500000);
    p.mark(0, 501000);
    CHECK(p.end(501000, 50'000) == 1000);
    CHECK(p.window_text(names, 50'000) == "ticks 2, max 400.3 ms (c), above 50 ms 1 (1 in all)");
    p.take_window();
    CHECK(p.window_text(names, 50'000) == "ticks 0, max 0.0 ms (a), above 50 ms 0 (1 in all)");
    CHECK(p.end(600000, 50'000) == 0);  // no tick going on
}

// ---------------------------------------------------------------- captures

void test_capture_file() {
    capture::Record a;
    a.t_us = 0x123456789ull;
    a.dir = capture::Dir::ClientToServer;
    a.data = packet(2490, 14);
    a.size = static_cast<uint16_t>(a.data.size());
    a.session = 4;
    a.thread = 77;
    capture::Record b;
    b.t_us = 0x12345678Aull;
    b.dir = capture::Dir::ServerToClient;
    b.data = packet(2005, 1019);
    b.size = 30000;  // truncated (version 1 kept 1024 bytes)
    // P8 session 8 (p8-impl-log-async.md §1.3): a gap record where the sniffer's disk queue lost 7 records.
    const capture::Record gap = capture::gap_record(0x123456789ull, 7);
    CHECK(gap.is_gap() && !a.is_gap() && gap.dir == capture::Dir::ServerToClient && gap.data.empty());
    Bytes file = capture::encode_header(2, 0x6AB28F00);
    for (const auto& r : {a, gap, b}) {
        const Bytes e = capture::encode_record(r);
        CHECK(e.size() == capture::kRecordHeaderSize + r.data.size());
        file.insert(file.end(), e.begin(), e.end());
    }
    file.push_back(0);  // a partial record at the end (game still writing)

    wchar_t dir[MAX_PATH], path[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    GetTempFileNameW(dir, L"cdk", 0, path);
    FILE* f = nullptr;
    _wfopen_s(&f, path, L"wb");
    CHECK(f != nullptr);
    if (!f) return;
    std::fwrite(file.data(), 1, file.size(), f);
    std::fclose(f);

    capture::Reader r;
    CHECK(r.open(path) && r.version() == 2 && r.pe_timestamp() == 0x6AB28F00);
    auto ra = r.next();
    CHECK(ra && ra->t_us == a.t_us && ra->dir == a.dir && ra->opcode() == 2490 && ra->whole() &&
          ra->session == 4 && ra->thread == 77 && ra->data == a.data);
    // The existing reader takes the gap as an ordinary (empty, whole) S>C record: format unchanged.
    auto rg = r.next();
    CHECK(rg && rg->is_gap() && rg->thread == 7 && rg->whole() && rg->opcode() == 0 &&
          rg->dir == capture::Dir::ServerToClient);
    auto rb = r.next();
    CHECK(rb && rb->dir == capture::Dir::ServerToClient && !rb->whole() && rb->size == 30000 &&
          rb->data.size() == 1024);
    CHECK(!r.next() && !r.error().empty());
    DeleteFileW(path);

    capture::Reader bad;
    CHECK(!bad.open(L"Z:/no/such/capture.bin"));
    uint32_t v = 0, ts = 0;
    const Bytes not_cdpk = {'C', 'D', 'P', 'X', 2, 0, 0, 0, 0, 0, 0, 0};
    CHECK(!capture::parse_header(not_cdpk.data(), not_cdpk.size(), v, ts));
}

// ---------------------------------------------------------------- script player

void test_script_parse() {
    std::string err;
    auto s = troc::parse_script(R"(
# E2
var ACCOUNT u64 1
send crypto 2319 -1 0400            # comment
expect 2840 5000
send login 2490 -1 01000000000000000000
put u64 0 ACCOUNT
learn USER_KEY u32 0x089B 0
expect 2716
wait 200
reply 3097 2624 0 000000000000000000000000
put u32 0 USER_KEY
end
send never 1 0 -
)", &err);
    CHECK(s.has_value());
    if (!s) {
        std::printf("  %s\n", err.c_str());
        return;
    }
    CHECK(s->steps.size() == 6 && s->learns.size() == 1 && s->vars.at("ACCOUNT") == 1);
    CHECK(s->steps[1].ms == 5000 && s->steps[3].ms == troc::ScriptPlayer::kDefaultExpectMs);
    CHECK(s->steps[5].kind == troc::ScriptStep::Kind::Reply && s->steps[5].on_opcode == 3097);
    CHECK(s->learns[0].opcode == 0x089B);

    const char* bad[] = {
        "send x 1 0 abc",                 // odd hex
        "send x 70000 0 -",               // opcode
        "send x 1 200 -",                 // slot
        "put u32 0 X",                    // put without send
        "send x 1 0 0000\nput u32 0 X",   // outside the payload / unknown var
        "send x 1 0 00000000\nput u32 0 NOPE",
        "expect",
        "frobnicate",
        "var A u128 1",
    };
    for (const char* b : bad) {
        std::string e;
        CHECK(!troc::parse_script(b, &e) && e.rfind("line ", 0) == 0);
    }
}

void test_script_player() {
    auto s = troc::parse_script(R"(
var ACCOUNT u64 1
send crypto 2319 -1 0400
expect 2840 1000
send login 2490 -1 01000000000000000000
put u64 0 ACCOUNT
learn USER_KEY u32 2203 0
learn CHAR u64 2213 5
expect 2716
send character 3093 -1 04ffffffffffffff7f01000000
put u64 1 CHAR
wait 100
send done 2445 0 01
reply 3097 2624 0 000000000000000000000000
put u32 0 USER_KEY
)", nullptr);
    CHECK(s.has_value());
    if (!s) return;
    troc::ScriptPlayer p(*s);
    p.set_var("ACCOUNT", 0x1234);
    uint32_t t = 1000;
    auto out = p.tick(t);
    CHECK(out.size() == 1 && troc::parse(out[0])->opcode == 2319);
    CHECK(p.tick(t + 500).empty());  // waiting for 2840
    // An Ack that arrived BEFORE the send would not count; this one is after.
    p.on_server_packet(troc::make(2840, -1, Bytes(4, 0)), t + 600);
    out = p.tick(t + 600);
    CHECK(out.size() == 1);
    auto login = troc::parse(out[0]);
    CHECK(login && login->opcode == 2490 && login->payload[0] == 0x34 && login->payload[1] == 0x12);
    // The user's acks: learn the key and the character number.
    Bytes start(8, 0);
    start[0] = 0x05;
    start[1] = 0x17;
    start[2] = 0x10;
    start[3] = 0x90;
    p.on_server_packet(troc::make(2203, -1, start), t + 700);
    Bytes lobby(13, 0);
    for (int i = 0; i < 8; ++i) lobby[5 + i] = static_cast<uint8_t>(0x10 + i);
    p.on_server_packet(troc::make(2213, -1, lobby), t + 700);
    CHECK(p.var("USER_KEY") == 0x90101705u);
    CHECK(p.tick(t + 800).empty());  // still waiting for 2716
    p.on_server_packet(troc::make(2716, -1, {}), t + 900);
    out = p.tick(t + 900);
    CHECK(out.size() == 1);
    auto ch = troc::parse(out[0]);
    CHECK(ch && ch->opcode == 3093 && ch->payload[1] == 0x10 && ch->payload[8] == 0x17 && ch->payload[9] == 1);
    // A reply fires whenever its trigger arrives, with learned variables.
    p.on_server_packet(troc::make(3097, -1, Bytes(12, 0)), t + 950);
    out = p.tick(t + 950);  // the reply; the wait of 100 ms is not over
    CHECK(out.size() == 1 && troc::parse(out[0])->opcode == 2624 && out[0][5] == 0x05 && out[0][8] == 0x90);
    out = p.tick(t + 1001);
    CHECK(out.size() == 1 && troc::parse(out[0])->opcode == 2445);
    CHECK(p.state() == troc::ScriptPlayer::State::Done && p.sent() == 4);

    // Timeout: the expect fails, nothing more is sent.
    troc::ScriptPlayer q(*s);
    CHECK(q.tick(0).size() == 1);
    CHECK(q.tick(999).empty() && q.state() == troc::ScriptPlayer::State::Running);
    CHECK(q.tick(1000).empty() && q.state() == troc::ScriptPlayer::State::Failed);
    CHECK(q.error().find("2840") != std::string::npos);

    // C4: logout_session sends the native 3-byte goodbye, and its 7-byte Acks
    // can be expected.
    auto lo = troc::parse_script("send x 2445 0 00\nlogout_session\nexpect 2003 1000\nexpect 2002 1000\n", nullptr);
    CHECK(lo.has_value());
    CHECK(!troc::parse_script("logout_session 1\n", nullptr));
    CHECK(!troc::parse_script("logout_session\nput u32 0 K\n", nullptr));  // nothing to put into
    // 2001-2003 only exist as internal messages: a send/reply with them is refused.
    std::string why;
    CHECK(!troc::parse_script("send bye 2001 -1 -\n", &why) && why.find("logout_session") != std::string::npos);
    CHECK(!troc::parse_script("reply 2840 2003 -1 00000000\n", nullptr));
    if (lo) {
        troc::ScriptPlayer pl(*lo);
        auto o = pl.tick(0);
        CHECK(o.size() == 2 && (o[1] == Bytes{0xD1, 0x07, 0xFF}));
        pl.on_server_packet(Bytes{0xD3, 0x07, 0xFF, 0x04, 0x00, 0x00, 0x00}, 10);
        pl.on_server_packet(Bytes{0xD2, 0x07, 0xFF, 0x04, 0x00, 0x00, 0x00}, 10);
        CHECK(pl.tick(10).empty() && pl.state() == troc::ScriptPlayer::State::Done && pl.sent() == 2);
    }

    // A put of a variable not learned yet fails the player.
    auto r = troc::parse_script("learn K u32 1 0\nsend a 5 0 00000000\nput u32 0 K\n", nullptr);
    CHECK(r.has_value());
    if (r) {
        troc::ScriptPlayer pr(*r);
        CHECK(pr.tick(0).empty() && pr.state() == troc::ScriptPlayer::State::Failed);
    }
}

// ---------------------------------------------------------------- D-53r: learn_child

Bytes from_hex(std::string_view h) {
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
    return out;
}

void put32(Bytes& b, size_t o, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[o + i] = static_cast<uint8_t>(v >> (8 * i));
}

uint32_t get32(std::span<const uint8_t> b, size_t o) {
    return static_cast<uint32_t>(b[o]) | static_cast<uint32_t>(b[o + 1]) << 8 | static_cast<uint32_t>(b[o + 2]) << 16 |
           static_cast<uint32_t>(b[o + 3]) << 24;
}

// The CharacterControl block of user 2's hatch, bytes +0x1200..+0x129F of its
// record in D:\cdmp-grabaciones\c4r_d53.bin #7439 (key 0xB0100228, owner
// 0x90100226, 9244 bytes): layer 0 = hash 0x866C7489, layer 1 empty, the
// app_xml path, restore 0 at +0x1294.
constexpr std::string_view kHatchCc =
    "00000089746c868d62010000000000010000000000000000000000000000000000ff660000006368617261637465722f617070656172616e"
    "63652f325f6d6f6e2f63645f6d303030325f30305f666f7572666565742f63645f6d303030325f30305f68617463682f63645f6d30303032"
    "5f30305f68617463685f303030315f30303030302e6170705f786d6c01000000000000000000b9c3bd80000000000000";

// An actor record: u8 type, u32 key, u32 owner, u8 slot, then filler; a CC
// block (if any) at +0x1200, as in the real hatch record.
Bytes actor_record(uint8_t type, uint32_t key, uint32_t owner, size_t size, bool with_cc) {
    Bytes r(size, 0);
    r[0] = type;
    put32(r, 1, key);
    put32(r, 5, owner);
    r[9] = 1;
    if (with_cc) {
        const Bytes cc = from_hex(kHatchCc);
        std::copy(cc.begin(), cc.end(), r.begin() + 0x1200);
    }
    return r;
}

Bytes user_record(uint32_t user) {
    Bytes r(9, 0);
    put32(r, 1, user);
    return r;
}

Bytes load_payload(const std::vector<Bytes>& records) {
    Bytes p;
    for (const auto& r : records) {
        p.push_back(static_cast<uint8_t>(r.size()));
        p.push_back(static_cast<uint8_t>(r.size() >> 8));
        p.insert(p.end(), r.begin(), r.end());
    }
    return p;
}

constexpr uint32_t kUser2 = 0x90100226, kHost = 0x90100000;

// A mixed ActorLoadDataAck like c1g #944 + #7431: the host's user record and
// child, user 2's character (type 1), user 2's user record and its hatch.
Bytes mixed_2005() {
    return load_payload({user_record(kHost), actor_record(6, 0xB0100002, kHost, 0x1300, true),
                         actor_record(1, 0xA0100227, kUser2, 0x40, false), user_record(kUser2),
                         actor_record(6, 0xB0100228, kUser2, 9244, true)});
}

void test_child_records() {
    const Bytes p = mixed_2005();
    auto recs = troc::split_actor_records(p);
    CHECK(recs && recs->size() == 5);
    if (recs && recs->size() == 5) CHECK((*recs)[0].size() == 9 && (*recs)[4].size() == 9244);

    auto c = troc::find_child_record(p, kUser2, 0x70);
    CHECK(c && c->key == 0xB0100228 && c->type == 6 && c->slot == 1 && c->index == 4 && c->count == 5);
    CHECK(c && c->record.size() == 9244);
    // The host's own child is not user 2's; type 6 not asked for; nobody's child.
    auto h = troc::find_child_record(p, kHost, 0x70);
    CHECK(h && h->key == 0xB0100002 && h->index == 1);
    CHECK(!troc::find_child_record(p, kUser2, 1 << 4 | 1 << 5));
    CHECK(!troc::find_child_record(p, 0x90100999, 0x70));
    // The character (type 1, key class 0xA) is never a child, even with type 1 in the mask.
    CHECK(!troc::find_child_record(load_payload({actor_record(1, 0xA0100227, kUser2, 0x40, false)}), kUser2, 0xFF));
    // Key class other than 0xB, a short record, a 9-byte record that looks like one: skipped.
    CHECK(!troc::find_child_record(load_payload({actor_record(6, 0xA0100228, kUser2, 0x40, false)}), kUser2, 0x70));
    Bytes nine(9, 0);
    nine[0] = 6;
    put32(nine, 1, 0xB0100228);
    put32(nine, 5, kUser2);
    CHECK(!troc::find_child_record(load_payload({nine}), kUser2, 0x70));

    // The CC block of the real hatch: found by its grammar at +0x1200.
    if (c) {
        auto cc = troc::find_cc_block(c->record);
        CHECK(cc && cc->offset == 0x1200 && cc->layer0_hash == 0x866C7489u && cc->restore == 0);
    }
    // Two blocks (or none) in one record: ambiguous, nothing.
    Bytes two = actor_record(6, 0xB0100228, kUser2, 0x1400, true);
    const Bytes cc = from_hex(kHatchCc);
    std::copy(cc.begin(), cc.end(), two.begin() + 0x1300);
    CHECK(!troc::find_cc_block(two));
    CHECK(!troc::find_cc_block(actor_record(6, 0xB0100228, kUser2, 0x1300, false)));
    // A block cut at the restore byte does not parse.
    Bytes cut = actor_record(6, 0xB0100228, kUser2, 0x1300, true);
    cut.resize(0x1294);
    CHECK(!troc::find_cc_block(cut));

    // Malformed payloads: nothing at all, not even the records before the fault.
    Bytes zero_len = p;
    zero_len.push_back(0);
    zero_len.push_back(0);
    CHECK(!troc::split_actor_records(zero_len) && !troc::find_child_record(zero_len, kUser2, 0x70));
    Bytes odd = p;
    odd.push_back(5);  // half a length
    CHECK(!troc::split_actor_records(odd) && !troc::find_child_record(odd, kUser2, 0x70));
    Bytes past = p;
    past.push_back(0x10);
    past.push_back(0);
    past.push_back(6);  // says 16 bytes, has 1
    CHECK(!troc::split_actor_records(past) && !troc::find_child_record(past, kUser2, 0x70));
    Bytes cut_last = p;
    cut_last.pop_back();  // the hatch record is one byte short of its length
    CHECK(!troc::split_actor_records(cut_last) && !troc::find_child_record(cut_last, kUser2, 0x70));
    CHECK(troc::split_actor_records({}) && troc::split_actor_records({})->empty());
}

// ---------------------------------------------------------------- P8 U2: learn_2661 (research/s25/tiendas-u2.md)

Bytes from_hex(const char* h) {
    Bytes out;
    for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
        auto nib = [](char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
        out.push_back(static_cast<uint8_t>(nib(h[i]) << 4 | nib(h[i + 1])));
    }
    return out;
}

void test_script_learn_2661() {
    // The S12 host's butcher scene 0x197 (113 bytes: owner A0100001, hash 0x978345CA, bindings Kliff and B0100156).
    const Bytes butcher = from_hex(
        "04010010a0010010a0970100000000000001005e470f0000000000ca4583975e470f00d4d426c68fe21844e90674c5875e2cc000000000"
        "00000000000000000000000000ffffff7f01000000000000000000ffffffffffffffff0d02000020010010a005000004000020560110b0"
        "050000");
    CHECK(butcher.size() == 113);
    const auto r = troc::parse_prepare_2661(butcher);
    CHECK(r && r->owner == 0xA0100001u && r->seq == 0x197 && r->hash == 0x978345CAu && r->npc() == 0xB0100156u);
    CHECK(r && r->bindings.size() == 2 && r->bindings[1].node == 0x20000004u && r->npc(0x20000004) == 0xB0100156u);
    CHECK(r && r->npc(0x20000002) == 0);  // the Kliff's node: not an NPC
    CHECK(r && r->npc(0x20000099) == 0);
    CHECK(!troc::parse_prepare_2661(std::span<const uint8_t>(butcher.data(), 112)));  // not 91 + 11 n
    CHECK(!troc::parse_prepare_2661(std::span<const uint8_t>(butcher.data(), 90)));
    const auto none = troc::parse_prepare_2661(std::span<const uint8_t>(butcher.data(), 102));  // Kliff's binding only
    CHECK(none && none->npc() == 0);

    std::string err;
    const char* good = "learn PLAYER_KEY u32 2756 0\nvar SHOP_HASH u32 0x978345CA\nlearn_2661 SEQ NPC SHOP_HASH\n"
                       "send a 1002 0 00\nexpect_learned SEQ 1000\nsend pre 2671 0 0000000000000000\n"
                       "put u32 0 PLAYER_KEY\nput u32 4 NPC\nsend br 2436 0 0000000000000000060000000000\n"
                       "put u64 0 SEQ\n";
    auto s = troc::parse_script(good, &err);
    CHECK(s.has_value());
    if (!s) {
        std::printf("  %s\n", err.c_str());
        return;
    }
    CHECK(s->prepares.size() == 1 && s->prepares[0].owner_var == "PLAYER_KEY" && s->prepares[0].hash_var == "SHOP_HASH");
    const char* bad[] = {
        "learn_2661 SEQ NPC H",                              // HASH never declared
        "var H u32 1\nlearn_2661 SEQ NPC H NOPE",            // OWNER never declared
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 SEQ SEQ H",  // the same variable twice
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 SEQ NPC",
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 SEQ NPC H PLAYER_KEY NODE",  // NODE never declared
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 H NPC H",                    // an input as SEQ
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 SEQ PLAYER_KEY H",           // an input as NPC
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 SEQ NPC H\nsend a 1 0 0000000000000000\nput u32 0 SEQ",
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 SEQ NPC H\nsend a 1 0 0000000000000000\nput u64 0 NPC",
        "var H u32 1\nvar PLAYER_KEY u32 2\nlearn_2661 SEQ NPC H PLAYER_KEY N X",
    };
    for (const char* b : bad) {
        std::string e;
        CHECK(!troc::parse_script(b, &e) && e.rfind("line ", 0) == 0);
    }
    // Owner and hash must match; the last fitting 2661 wins; then the Reqs carry them.
    troc::ScriptPlayer p(*s);
    CHECK(p.tick(0).size() == 1);
    p.on_server_packet(troc::make(2756, -1, Bytes{0x36, 0x03, 0x10, 0xA0}), 10);  // PLAYER_KEY 0xA0100336
    p.on_server_packet(troc::make(2661, -1, butcher), 20);                          // the host's: not ours
    CHECK(!p.learned("SEQ") && p.take_notes().empty());
    Bytes mine = butcher;
    mine[5] = 0x36;
    mine[6] = 0x03;  // owner 0xA0100336
    mine[9] = 0xC4;
    mine[10] = 0x02;  // sequencer 0x2C4
    Bytes other_shop = mine;
    other_shop[27] = 0x61;  // another resource hash
    p.on_server_packet(troc::make(2661, -1, other_shop), 30);
    CHECK(!p.learned("SEQ"));
    p.on_server_packet(troc::make(2661, -1, mine), 40);
    CHECK(p.var("SEQ") == 0x2C4u && p.var("NPC") == 0xB0100156u);
    auto notes = p.take_notes();
    CHECK(notes.size() == 1 && notes[0].find("SEQ = 0x2C4") != std::string::npos);
    mine[9] = 0xD0;  // a re-prepared scene (a drain and a new arm): the last wins
    p.on_server_packet(troc::make(2661, -1, mine), 50);
    CHECK(p.var("SEQ") == 0x2D0u);
    auto out = p.tick(60);
    CHECK(out.size() == 2 && p.state() == troc::ScriptPlayer::State::Done);
    if (out.size() == 2) {
        auto a = troc::parse(out[0]);
        auto b = troc::parse(out[1]);
        CHECK(a && a->opcode == 2671 && get32(a->payload, 0) == 0xA0100336u && get32(a->payload, 4) == 0xB0100156u);
        CHECK(b && b->opcode == 2436 && get32(b->payload, 0) == 0x2D0u && b->payload[8] == 6);
    }
    // With NODE: the shopkeeper's link only (here the butcher's node 0x20000004; a wrong node learns no NPC).
    auto sn = troc::parse_script("learn PLAYER_KEY u32 2756 0\nvar SHOP_HASH u32 0x978345CA\nvar NODE u32 0x20000004\n"
                                 "var BAD u32 0x20000008\nlearn_2661 SEQ NPC SHOP_HASH PLAYER_KEY NODE\n"
                                 "learn_2661 SEQ2 NPC2 SHOP_HASH PLAYER_KEY BAD\n", &err);
    CHECK(sn.has_value());
    if (sn) {
        troc::ScriptPlayer q(*sn);
        q.on_server_packet(troc::make(2756, -1, Bytes{0x36, 0x03, 0x10, 0xA0}), 0);
        q.on_server_packet(troc::make(2661, -1, mine), 0);
        CHECK(q.var("NPC") == 0xB0100156u && q.var("SEQ") == 0x2D0u);
        CHECK(q.learned("SEQ2") && !q.learned("NPC2"));
    }
}

void test_script_learn_child() {
    std::string err;
    const char* text = R"(
learn USER_KEY u32 2646 0
learn_child CHILD_KEY 2005 USER_KEY 6
learn_child_hash CHILD_HASH
var CHILD_HASH u32 0x11111111
send a 1002 0 00
expect_learned CHILD_KEY 1000
send child 2223 0 000000000000000000000000
put u32 0 CHILD_KEY
put u32 8 CHILD_HASH
)";
    auto s = troc::parse_script(text, &err);
    CHECK(s.has_value());
    if (!s) {
        std::printf("  %s\n", err.c_str());
        return;
    }
    CHECK(s->child && s->child->opcode == 2005 && s->child->type_mask == 1 << 6 && s->child->hash_var == "CHILD_HASH");
    CHECK(s->steps.size() == 3 && s->steps[1].kind == troc::ScriptStep::Kind::ExpectLearned && s->steps[1].ms == 1000);
    auto d = troc::parse_script("learn U u32 1 0\nlearn_child K 2005 U\n", nullptr);
    CHECK(d && d->child->type_mask == 0x70);  // 4,5,6 by default
    auto l = troc::parse_script("var U u32 1\nlearn_child K 0x7D5 U 4,6\n", nullptr);
    CHECK(l && l->child->type_mask == (1 << 4 | 1 << 6) && l->child->opcode == 2005);

    const char* bad[] = {
        "learn_child K 2005 NOPE",                                     // owner never declared or learned
        "var U u32 1\nlearn_child K 2005 U 7",                          // not a child type
        "var U u32 1\nlearn_child K 2005 U 4,,6",
        "var U u32 1\nlearn_child K 70000 U",
        "var U u32 1\nlearn_child K 2005",
        "var U u32 1\nlearn_child K 2005 U\nlearn_child J 2005 U",      // one per script
        "learn_child_hash H",                                          // without learn_child
        "var U u32 1\nlearn_child K 2005 U\nlearn_child_hash K",       // its own variable
        "var U u32 1\nlearn_child K 2005 U\nlearn_child_hash H\nlearn_child_hash G",
        "var X u32 1\nexpect_learned X",                               // declared, never learned
        "expect_learned",
        "learn K u32 1 0\nexpect_learned K abc",
        "send a 1 0 00000000\nput u32 0 K",                            // K unknown
    };
    for (const char* b : bad) {
        std::string e;
        CHECK(!troc::parse_script(b, &e) && e.rfind("line ", 0) == 0);
    }

    const Bytes user_ack = {0x26, 0x02, 0x10, 0x90, 0, 0, 0, 0};  // MainUserDataStartAck: USER_KEY 0x90100226
    // Learned from the mixed 2005, put into the next Req.
    {
        troc::ScriptPlayer p(*s);
        CHECK(p.tick(0).size() == 1);
        CHECK(p.tick(100).empty() && p.describe().find("waiting to learn CHILD_KEY") != std::string::npos);
        p.on_server_packet(troc::make(2005, -1, mixed_2005()), 150);  // the owner is not known yet: nothing
        CHECK(!p.learned("CHILD_KEY") && p.take_notes().empty());
        p.on_server_packet(troc::make(2646, -1, user_ack), 200);
        Bytes bad_2005 = mixed_2005();
        bad_2005.push_back(1);
        p.on_server_packet(troc::make(2005, -1, bad_2005), 250);
        auto notes = p.take_notes();
        CHECK(notes.size() == 1 && notes[0].find("bad record length") != std::string::npos && !p.learned("CHILD_KEY"));
        CHECK(p.tick(250).empty());
        p.on_server_packet(troc::make(2005, -1, mixed_2005()), 300);
        CHECK(p.var("CHILD_KEY") == 0xB0100228u && p.var("CHILD_HASH") == 0x866C7489u && p.learned("CHILD_HASH"));
        notes = p.take_notes();
        CHECK(notes.size() == 1 && notes[0].find("CHILD_KEY = 0xB0100228") != std::string::npos &&
              notes[0].find("CHILD_HASH = 0x866C7489") != std::string::npos && notes[0].find("+0x1203") != std::string::npos);
        // A later child does not replace the first.
        p.on_server_packet(troc::make(2005, -1, load_payload({actor_record(6, 0xB0100300, kUser2, 0x40, false)})), 320);
        CHECK(p.var("CHILD_KEY") == 0xB0100228u && p.take_notes().empty());
        auto out = p.tick(350);
        CHECK(out.size() == 1 && p.state() == troc::ScriptPlayer::State::Done);
        if (out.size() == 1) {
            auto v = troc::parse(out[0]);
            CHECK(v && v->opcode == 2223 && get32(v->payload, 0) == 0xB0100228u && get32(v->payload, 8) == 0x866C7489u);
        }
    }
    // Learned before the step: it passes at once. No CC block: the hash keeps its var value.
    {
        troc::ScriptPlayer p(*s);
        p.on_server_packet(troc::make(2646, -1, user_ack), 0);
        p.on_server_packet(troc::make(2005, -1, load_payload({actor_record(6, 0xB0100301, kUser2, 0x40, false)})), 0);
        auto notes = p.take_notes();
        CHECK(notes.size() == 1 && notes[0].find("CHILD_HASH not learned") != std::string::npos &&
              notes[0].find("keeps 0x11111111") != std::string::npos);
        auto out = p.tick(0);
        CHECK(out.size() == 2 && p.state() == troc::ScriptPlayer::State::Done);
        if (out.size() == 2) CHECK(get32(troc::parse(out[1])->payload, 8) == 0x11111111u);
    }
    // The command line wins over a learned value.
    {
        troc::ScriptPlayer p(*s);
        p.set_var("CHILD_HASH", 0x94D333D6);
        p.on_server_packet(troc::make(2646, -1, user_ack), 0);
        p.on_server_packet(troc::make(2005, -1, mixed_2005()), 0);
        auto out = p.tick(0);
        CHECK(out.size() == 2 && p.var("CHILD_HASH") == 0x94D333D6u);
        if (out.size() == 2) CHECK(get32(troc::parse(out[1])->payload, 8) == 0x94D333D6u);
    }
    // No child within the timeout: the player fails and sends nothing more.
    {
        troc::ScriptPlayer p(*s);
        CHECK(p.tick(0).size() == 1);
        CHECK(p.tick(999).empty() && p.state() == troc::ScriptPlayer::State::Running);
        CHECK(p.tick(1000).empty() && p.state() == troc::ScriptPlayer::State::Failed);
        CHECK(p.error().find("CHILD_KEY not learned") != std::string::npos);
    }
}

// login_e3lc00bye_child_112627.troc against a fake server, start to goodbye:
// the child's first action carries the learned key, owner, hash and position.
void test_child_script_flow() {
    std::ifstream f(std::filesystem::path(std::string(CDMP_SOURCE_DIR)) / "docs/research/data/login_e3lc00bye_child_112627.troc");
    CHECK(f.good());
    std::stringstream ss;
    ss << f.rdbuf();
    std::string err;
    auto s = troc::parse_script(ss.str(), &err);
    CHECK(s.has_value());
    if (!s) {
        std::printf("  %s\n", err.c_str());
        return;
    }
    troc::ScriptPlayer p(*s);
    p.set_var("SAVE_SLOT", 108);
    const Bytes user_ack = {0x26, 0x02, 0x10, 0x90, 0, 0, 0, 0};
    const Bytes player_ack = {0x27, 0x02, 0x10, 0xA0, 0, 0, 0, 0};
    auto move_field = [](float x, float y, float z) {
        Bytes b(65, 0);
        std::memcpy(&b[25], &x, 4);
        std::memcpy(&b[29], &y, 4);
        std::memcpy(&b[33], &z, 4);
        return b;
    };
    std::vector<Bytes> sent;
    int mfc = 0;
    for (uint32_t t = 0; t < 60000 && p.state() == troc::ScriptPlayer::State::Running; t += 50) {
        for (auto& o : p.tick(t)) {
            auto v = troc::parse_wire(o, troc::Dir::ToHostServer);
            CHECK(v.has_value());
            if (!v) continue;
            sent.push_back(o);
            switch (v->opcode) {
                case 2319: p.on_server_packet(troc::make(2840, -1, Bytes(4, 0)), t); break;
                case 2490:
                    p.on_server_packet(troc::make(2646, -1, user_ack), t);
                    p.on_server_packet(troc::make(2869, -1, Bytes(13, 0x7F)), t);  // CharacterLobbyDataAck
                    p.on_server_packet(troc::make(2716, -1, {}), t);
                    break;
                case 3093:
                    p.on_server_packet(troc::make(2756, -1, player_ack), t);
                    p.on_server_packet(troc::make(2174, -1, move_field(0, 1000, 0)), t);
                    break;
                case 2437: p.on_server_packet(troc::make(2174, -1, move_field(-10717.79f, 620.17f, -3914.56f)), t); break;
                case 2549:
                    // The shared load: the child's 2005 right after the Ack, as in c4r_d53.
                    p.on_server_packet(troc::make(2144, 0, {}), t);
                    if (++mfc == 2) p.on_server_packet(troc::make(2005, -1, mixed_2005()), t);
                    break;
                case 2445: p.on_server_packet(troc::make(2762, 0, {}), t); break;
                case 2001:
                    p.on_server_packet(Bytes{0xD3, 0x07, 0xFF, 0x04, 0x00, 0x00, 0x00}, t);
                    p.on_server_packet(Bytes{0xD2, 0x07, 0xFF, 0x04, 0x00, 0x00, 0x00}, t);
                    break;
                default: break;
            }
        }
    }
    CHECK(p.state() == troc::ScriptPlayer::State::Done);
    if (p.state() != troc::ScriptPlayer::State::Done) std::printf("  %s\n", p.describe().c_str());
    std::vector<troc::PacketView> actions;
    for (const auto& o : sent) {
        auto v = troc::parse(o);
        if (v && v->opcode == 2223) actions.push_back(*v);
    }
    CHECK(actions.size() == 2);
    if (actions.size() != 2) return;
    CHECK(get32(actions[0].payload, 0) == 0xA0100227u);  // 4b: Kliff, unchanged
    const auto& a = actions[1].payload;
    CHECK(a.size() == 725 && a[0x2D4] == 0);
    CHECK(get32(a, 0) == 0xB0100228u && get32(a, 0x16C) == 0xA0100227u && get32(a, 8) == 0x866C7489u);
    float x = 0, y = 0, z = 0;
    std::memcpy(&x, &a[0x8E], 4);
    std::memcpy(&y, &a[0x92], 4);
    std::memcpy(&z, &a[0x96], 4);
    CHECK(x == -10717.79f && y == 620.17f && z == -3914.56f);  // the last MoveFieldAck, not (0, 1000, 0)
    // The rest is the capture's (112627 #3449): quat, clock, the opaque u32.
    CHECK(get32(a, 0x15F) == 0x101F4u && get32(a, 0x2CA) == 0x101F4u && get32(a, 0x168) == 0x6BB08C54u);
    // Order: after the second MoveFieldCompleteReq, before LoadingCompleteReq #2; goodbye last.
    std::vector<uint16_t> ops;
    for (const auto& o : sent) ops.push_back(troc::parse_wire(o, troc::Dir::ToHostServer)->opcode);
    const std::vector<uint16_t> want = {2319, 2490, 3093, 2549, 2223, 2445, 2601, 2437, 2549, 2223, 2445, 2001};
    CHECK(ops == want);
}

// P8 S15 (p8-impl-viaje-rapido.md §11): login_e3lc00_travel_s14.troc (hand-made: the E3 login + the external
// review's suffix B) against a fake server: after the SECOND 2762, the guest's 2283 of session 14 (53 bytes, exact)
// and, 1953 ms later, its empty 2437; nothing after them; the script ends.
void test_travel_script_flow() {
    std::ifstream f(std::filesystem::u8path(std::string(CDMP_SOURCE_DIR) + "/docs/research/data/login_e3lc00_travel_s14.troc"));
    CHECK(f.good());
    std::stringstream ss;
    ss << f.rdbuf();
    std::string err;
    auto s = troc::parse_script(ss.str(), &err);
    CHECK(s.has_value());
    if (!s) {
        std::printf("  %s\n", err.c_str());
        return;
    }
    troc::ScriptPlayer p(*s);
    p.set_var("SAVE_SLOT", 1);
    const Bytes user_ack = {0x4B, 0x0A, 0x10, 0x90, 0, 0, 0, 0};
    const Bytes player_ack = {0x4C, 0x0A, 0x10, 0xA0, 0, 0, 0, 0};
    std::vector<std::pair<uint32_t, Bytes>> sent;
    int lc = 0;
    uint32_t t_second_2762 = 0;
    for (uint32_t t = 0; t < 120000 && p.state() == troc::ScriptPlayer::State::Running; t += 1) {
        for (auto& o : p.tick(t)) {
            auto v = troc::parse_wire(o, troc::Dir::ToHostServer);
            CHECK(v.has_value());
            if (!v) continue;
            sent.emplace_back(t, o);
            switch (v->opcode) {
                case 2319: p.on_server_packet(troc::make(2840, -1, Bytes(4, 0)), t); break;
                case 2490:
                    p.on_server_packet(troc::make(2646, -1, user_ack), t);
                    p.on_server_packet(troc::make(2869, -1, Bytes(13, 0x7F)), t);
                    p.on_server_packet(troc::make(2716, -1, {}), t);
                    break;
                case 3093:
                    p.on_server_packet(troc::make(2756, -1, player_ack), t);
                    p.on_server_packet(troc::make(2174, -1, Bytes(65, 0)), t);
                    break;
                case 2437:
                    if (lc < 2) p.on_server_packet(troc::make(2174, -1, Bytes(65, 0)), t);
                    break;
                case 2549: p.on_server_packet(troc::make(2144, 0, {}), t); break;
                case 2445:
                    p.on_server_packet(troc::make(2762, 0, {}), t);
                    if (++lc == 2) t_second_2762 = t;
                    break;
                default: break;
            }
        }
    }
    CHECK(p.state() == troc::ScriptPlayer::State::Done);
    if (p.state() != troc::ScriptPlayer::State::Done) std::printf("  %s\n", p.describe().c_str());
    std::vector<uint16_t> ops;
    for (const auto& [t, o] : sent) ops.push_back(troc::parse_wire(o, troc::Dir::ToHostServer)->opcode);
    const std::vector<uint16_t> want = {2319, 2490, 3093, 2549, 2223, 2445, 2601, 2437, 2549, 2445, 2283, 2437};
    CHECK(ops == want);
    if (ops != want || sent.size() != want.size()) return;
    const auto reload = troc::parse(sent[10].second);
    const Bytes s14 = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x09,
                       0x26, 0xc6, 0xa2, 0x4d, 0x1b, 0x44, 0x2c, 0x54, 0x6e, 0xc5, 0x00, 0x00, 0x00, 0x00,
                       0x4b, 0x13, 0xd6, 0x3d, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x98, 0x7e, 0x3f, 0x00, 0x00,
                       0x80, 0x3f, 0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x80, 0x3f, 0x01};
    CHECK(reload && reload->payload.size() == 53 && Bytes(reload->payload.begin(), reload->payload.end()) == s14);
    const auto loading = troc::parse(sent[11].second);
    CHECK(loading && loading->payload.empty());
    // 5 s after the second 2762 (plus the expect_learned checks, immediate), then 1953 ms between the two.
    CHECK(sent[10].first >= t_second_2762 + 5000 && sent[10].first <= t_second_2762 + 5010);
    CHECK(sent[11].first - sent[10].first >= 1953 && sent[11].first - sent[10].first <= 1960);
}

// P8 S16 (p8-impl-viaje-rapido.md §12): login_e3lc00_travel_s14_b.troc = the S15 script + a tail: after the 2437 it
// waits for 2643 and 3066, sends the guest's empty 2873 2300 ms later, then a 3067 carrier 400 ms after it and expects
// the 2322 (a fake server answers the carrier with it). Without the 2322 the script fails at that expect.
void test_travel_script_b_flow() {
    std::ifstream f(
        std::filesystem::u8path(std::string(CDMP_SOURCE_DIR) + "/docs/research/data/login_e3lc00_travel_s14_b.troc"));
    CHECK(f.good());
    std::stringstream ss;
    ss << f.rdbuf();
    std::string err;
    auto s = troc::parse_script(ss.str(), &err);
    CHECK(s.has_value());
    if (!s) {
        std::printf("  %s\n", err.c_str());
        return;
    }
    for (const bool answer_2322 : {true, false}) {
        troc::ScriptPlayer p(*s);
        p.set_var("SAVE_SLOT", 1);
        const Bytes user_ack = {0x4B, 0x0A, 0x10, 0x90, 0, 0, 0, 0};
        const Bytes player_ack = {0x4C, 0x0A, 0x10, 0xA0, 0, 0, 0, 0};
        std::vector<std::pair<uint32_t, Bytes>> sent;
        int lc = 0;
        for (uint32_t t = 0; t < 120000 && p.state() == troc::ScriptPlayer::State::Running; t += 1) {
            for (auto& o : p.tick(t)) {
                auto v = troc::parse_wire(o, troc::Dir::ToHostServer);
                CHECK(v.has_value());
                if (!v) continue;
                sent.emplace_back(t, o);
                switch (v->opcode) {
                    case 2319: p.on_server_packet(troc::make(2840, -1, Bytes(4, 0)), t); break;
                    case 2490:
                        p.on_server_packet(troc::make(2646, -1, user_ack), t);
                        p.on_server_packet(troc::make(2869, -1, Bytes(13, 0x7F)), t);
                        p.on_server_packet(troc::make(2716, -1, {}), t);
                        break;
                    case 3093:
                        p.on_server_packet(troc::make(2756, -1, player_ack), t);
                        p.on_server_packet(troc::make(2174, -1, Bytes(65, 0)), t);
                        break;
                    case 2437:
                        if (lc < 2) {
                            p.on_server_packet(troc::make(2174, -1, Bytes(65, 0)), t);
                        } else {  // the reload: 0x2BCA3D0's 2643 (20 + 48 bytes) and 3066 (6 bytes)
                            p.on_server_packet(troc::make(2643, 0, Bytes(68, 0)), t);
                            p.on_server_packet(troc::make(3066, 0, Bytes(6, 0)), t);
                        }
                        break;
                    case 2549: p.on_server_packet(troc::make(2144, 0, {}), t); break;
                    case 2445:
                        p.on_server_packet(troc::make(2762, 0, {}), t);
                        ++lc;
                        break;
                    case 3067:
                        // observer_seq_copy_2322's copy of the HOST's 2322 (0xA0100001) comes first, whatever the
                        // fix does; only the one naming the peer's character (PLAYER_KEY 0xA0100A4C) may satisfy
                        // the expect (review of d09254d: a bare expect 2322 passed falsely)
                        p.on_server_packet(troc::make(2322, 0, Bytes{0x01, 0x00, 0x10, 0xA0}), t);
                        if (answer_2322) p.on_server_packet(troc::make(2322, 0, Bytes{0x4C, 0x0A, 0x10, 0xA0}), t);
                        break;
                    default: break;
                }
            }
        }
        std::vector<uint16_t> ops;
        for (const auto& [t, o] : sent) ops.push_back(troc::parse_wire(o, troc::Dir::ToHostServer)->opcode);
        const std::vector<uint16_t> want = {2319, 2490, 3093, 2549, 2223, 2445, 2601, 2437,
                                            2549, 2445, 2283, 2437, 2873, 3067};
        CHECK(ops == want);
        if (answer_2322) {
            CHECK(p.state() == troc::ScriptPlayer::State::Done);
            if (p.state() != troc::ScriptPlayer::State::Done) std::printf("  %s\n", p.describe().c_str());
        } else {
            CHECK(p.state() == troc::ScriptPlayer::State::Failed);  // no 2322: the expect fails, visibly
        }
        if (ops != want || sent.size() != want.size()) continue;
        const auto pre = troc::parse(sent[12].second);
        CHECK(pre && pre->payload.empty() && pre->slot == 0);
        const auto carrier = troc::parse(sent[13].second);
        CHECK(carrier && carrier->payload.size() == 8);
        CHECK(sent[12].first - sent[11].first >= 2300 && sent[12].first - sent[11].first <= 2310);
        CHECK(sent[13].first - sent[12].first >= 400 && sent[13].first - sent[12].first <= 410);
    }
}

// P8 S27 (docs/research/s25/reaparicion.md): login_e3lc00_revive_s27.troc = the E3 login + the revive of session 27:
// after the second 2762, ReviveLoadingReq 2362 (02 00) -> 2993, its empty 2437 -> 2643 + 3066, ReviveReq 2988 (its key,
// type 2), the empty 2873 60 ms later, a 3067 carrier 400 ms after it, the 2322 expected, then 2445 -> 2762. Without
// the 2322 (the host's key observer_milestone_reload_any off) the script fails at that expect.
void test_revive_script_flow() {
    std::ifstream f(
        std::filesystem::u8path(std::string(CDMP_SOURCE_DIR) + "/docs/research/data/login_e3lc00_revive_s27.troc"));
    CHECK(f.good());
    std::stringstream ss;
    ss << f.rdbuf();
    std::string err;
    auto s = troc::parse_script(ss.str(), &err);
    CHECK(s.has_value());
    if (!s) {
        std::printf("  %s\n", err.c_str());
        return;
    }
    for (const bool answer_2322 : {true, false}) {
        troc::ScriptPlayer p(*s);
        p.set_var("SAVE_SLOT", 1);
        const Bytes user_ack = {0x4B, 0x0A, 0x10, 0x90, 0, 0, 0, 0};
        const Bytes player_ack = {0x4C, 0x0A, 0x10, 0xA0, 0, 0, 0, 0};
        std::vector<std::pair<uint32_t, Bytes>> sent;
        int lc = 0;
        for (uint32_t t = 0; t < 120000 && p.state() == troc::ScriptPlayer::State::Running; t += 1) {
            for (auto& o : p.tick(t)) {
                auto v = troc::parse_wire(o, troc::Dir::ToHostServer);
                CHECK(v.has_value());
                if (!v) continue;
                sent.emplace_back(t, o);
                switch (v->opcode) {
                    case 2319: p.on_server_packet(troc::make(2840, -1, Bytes(4, 0)), t); break;
                    case 2490:
                        p.on_server_packet(troc::make(2646, -1, user_ack), t);
                        p.on_server_packet(troc::make(2869, -1, Bytes(13, 0x7F)), t);
                        p.on_server_packet(troc::make(2716, -1, {}), t);
                        break;
                    case 3093:
                        p.on_server_packet(troc::make(2756, -1, player_ack), t);
                        p.on_server_packet(troc::make(2174, -1, Bytes(65, 0)), t);
                        break;
                    case 2362: p.on_server_packet(troc::make(2993, 0, Bytes(9, 0)), t); break;
                    case 2437:
                        if (lc < 2) {
                            p.on_server_packet(troc::make(2174, -1, Bytes(65, 0)), t);
                        } else {  // the revive's reload in the same field (0x2BCA3D0)
                            p.on_server_packet(troc::make(2643, 0, Bytes(68, 0)), t);
                            p.on_server_packet(troc::make(3066, 0, Bytes(6, 0)), t);
                        }
                        break;
                    case 2549: p.on_server_packet(troc::make(2144, 0, {}), t); break;
                    case 2445:
                        p.on_server_packet(troc::make(2762, 0, {}), t);
                        ++lc;
                        break;
                    case 3067:
                        // observer_seq_copy_2322's copy of the HOST's 2322 (0xA0100001) comes first, whatever the
                        // fix does; only the one naming the peer's character (PLAYER_KEY 0xA0100A4C) may satisfy
                        // the expect (review of d09254d: a bare expect 2322 passed falsely)
                        p.on_server_packet(troc::make(2322, 0, Bytes{0x01, 0x00, 0x10, 0xA0}), t);
                        if (answer_2322) p.on_server_packet(troc::make(2322, 0, Bytes{0x4C, 0x0A, 0x10, 0xA0}), t);
                        break;
                    default: break;
                }
            }
        }
        std::vector<uint16_t> ops;
        for (const auto& [t, o] : sent) ops.push_back(troc::parse_wire(o, troc::Dir::ToHostServer)->opcode);
        std::vector<uint16_t> want = {2319, 2490, 3093, 2549, 2223, 2445, 2601, 2437,
                                      2549, 2445, 2362, 2437, 2988, 2873, 3067};
        if (answer_2322) want.push_back(2445);
        CHECK(ops == want);
        if (answer_2322) {
            CHECK(p.state() == troc::ScriptPlayer::State::Done);
            if (p.state() != troc::ScriptPlayer::State::Done) std::printf("  %s\n", p.describe().c_str());
        } else {
            CHECK(p.state() == troc::ScriptPlayer::State::Failed);  // no 2322: the expect fails, visibly
        }
        if (ops != want || sent.size() != want.size()) continue;
        const auto revive_loading = troc::parse(sent[10].second);
        CHECK(revive_loading && revive_loading->slot == 0 &&
              Bytes(revive_loading->payload.begin(), revive_loading->payload.end()) == Bytes({0x02, 0x00}));
        const auto loading = troc::parse(sent[11].second);
        CHECK(loading && loading->payload.empty());
        const auto revive = troc::parse(sent[12].second);
        CHECK(revive && revive->payload.size() == 8 && get32(revive->payload, 0) == 0xA0100A4Cu &&
              revive->payload[4] == 2 && revive->payload[5] == 0);
        const auto pre = troc::parse(sent[13].second);
        CHECK(pre && pre->payload.empty() && pre->slot == 0);
        const auto carrier = troc::parse(sent[14].second);
        CHECK(carrier && carrier->payload.size() == 8);
        CHECK(sent[11].first - sent[10].first >= 50 && sent[11].first - sent[10].first <= 60);
        CHECK(sent[13].first - sent[12].first >= 60 && sent[13].first - sent[12].first <= 70);
        CHECK(sent[14].first - sent[13].first >= 400 && sent[14].first - sent[13].first <= 410);
        if (answer_2322) {
            const auto done = troc::parse(sent[15].second);
            CHECK(done && done->payload.size() == 1 && done->payload[0] == 0);
        }
    }
}

// P8 S27 review: `expect OPCODE TIMEOUT TYPE OFFSET NAME` counts only an Ack holding NAME's value at OFFSET.
void test_expect_value() {
    std::string err;
    CHECK(!troc::parse_script("send A 2445 0 00\nexpect 2322 100 u32 0 NOPE\n", &err).has_value());
    CHECK(err.find("NOPE") != std::string::npos);
    CHECK(!troc::parse_script("expect 2322 100 u32 0\n", &err).has_value());
    CHECK(!troc::parse_script("var K u32 1\nexpect 2322 100 u33 0 K\n", &err).has_value());
    auto s = troc::parse_script("var K u32 0x11\nsend A 2445 0 00\nexpect 2322 100 u32 0 K\nsend B 2445 0 00\n", &err);
    CHECK(s.has_value());
    if (!s) return;
    {  // another value does not count; the right one does
        troc::ScriptPlayer p(*s);
        CHECK(p.tick(0).size() == 1);
        p.on_server_packet(troc::make(2322, 0, Bytes{0x22, 0, 0, 0}), 1);
        CHECK(p.tick(2).empty() && p.state() == troc::ScriptPlayer::State::Running);
        CHECK(p.describe().find("holding K") != std::string::npos);
        p.on_server_packet(troc::make(2322, 0, Bytes{0x11, 0, 0, 0}), 3);
        CHECK(p.tick(4).size() == 1);
        CHECK(p.state() == troc::ScriptPlayer::State::Done);
    }
    {  // only the wrong value: fails at the timeout, saying how many of any value came
        troc::ScriptPlayer p(*s);
        p.tick(0);
        p.on_server_packet(troc::make(2322, 0, Bytes{0x22, 0, 0, 0}), 1);
        p.on_server_packet(troc::make(2322, 0, Bytes{0x01}), 2);  // too short: ignored
        p.tick(50);
        CHECK(p.state() == troc::ScriptPlayer::State::Running);
        p.tick(101);
        CHECK(p.state() == troc::ScriptPlayer::State::Failed);
        CHECK(p.error().find("holding K") != std::string::npos && p.error().find("any value: 2") != std::string::npos);
    }
    {  // a variable learned later (the peer's PLAYER_KEY from 2756) is the one compared, at arrival time
        auto s2 = troc::parse_script(
            "learn K u32 2756 0\nsend A 2445 0 00\nexpect_learned K 100\nsend B 2445 0 00\nexpect 2322 100 u32 0 K\n", &err);
        CHECK(s2.has_value());
        if (!s2) return;
        troc::ScriptPlayer p(*s2);
        p.tick(0);
        p.on_server_packet(troc::make(2756, 0, Bytes{0x4C, 0x0A, 0x10, 0xA0}), 1);
        CHECK(p.tick(2).size() == 1);
        p.on_server_packet(troc::make(2322, 0, Bytes{0x4C, 0x0A, 0x10, 0xA0}), 3);
        p.tick(4);
        CHECK(p.state() == troc::ScriptPlayer::State::Done);
    }
}

// The scripts generated from the login capture (docs/research/data/*.troc)
// parse, and the E3 one plays its first steps.
void test_generated_scripts() {
    const char* names[] = {"login_e2_112627.troc", "login_e3_112627.troc", "login_e3opt_112627.troc",
                           "login_e3lc00_112627.troc", "login_e3lc00bye_112627.troc",
                           "login_e3lc00bye_child_112627.troc",
                           // Mid-load cuts (salida-en-carga.md §3): window A parking, A shared, B shared.
                           "login_e3lc00cut3_112627.troc", "login_e3lc00cut8_112627.troc",
                           "login_e3lc00cut9_112627.troc"};
    for (const char* n : names) {
        // The source path is UTF-8 (/utf-8); u8path keeps a path with accents working.
        std::ifstream f(std::filesystem::u8path(std::string(CDMP_SOURCE_DIR) + "/docs/research/data/" + n));
        CHECK(f.good());
        std::stringstream ss;
        ss << f.rdbuf();
        std::string err;
        auto s = troc::parse_script(ss.str(), &err);
        CHECK(s.has_value());
        if (!s) {
            std::printf("  %s: %s\n", n, err.c_str());
            continue;
        }
        troc::ScriptPlayer p(*s);
        auto out = p.tick(0);
        CHECK(out.size() == 1 && troc::parse(out[0])->opcode == 2319 && out[0].size() == 5 + 286);
    }
}

// ---------------------------------------------------------------- P6

void test_save_guard_paths() {
    using namespace saveguard;
    CHECK(normalize(LR"(C:/Users/User//AppData\Local\\)") == LR"(c:\users\user\appdata\local)");
    CHECK(normalize(LR"(\\?\C:\X\Save)") == LR"(c:\x\save)");
    CHECK(normalize(L"C:\\Usuarios\\JOS\u00C9") == L"c:\\usuarios\\jos\u00E9");
    const std::wstring dir = LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\save)";
    CHECK(is_under(L"c:/users/USER/appdata/local/pearl abyss/cd/save/1/save.save", dir));
    CHECK(is_under(dir, dir));
    CHECK(is_under(dir + L"\\", dir));
    CHECK(!is_under(LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\savegames\x)", dir));
    CHECK(!is_under(LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD)", dir));
    CHECK(!is_under(LR"(D:\SteamLibrary\cdmp.log)", dir));
    CHECK(!is_under(L"anything", L""));
}

void test_save_guard_policy() {
    using namespace saveguard;
    constexpr uint32_t kGenericRead = 0x80000000, kGenericWrite = 0x40000000, kDelete = 0x10000;
    constexpr uint32_t kOpenExisting = 3, kCreateAlways = 2, kOpenAlways = 4;
    CHECK(!create_may_write(kGenericRead, kOpenExisting, 0x80));
    CHECK(!create_may_write(0x80 /*FILE_READ_ATTRIBUTES*/, kOpenExisting, 0));
    CHECK(create_may_write(kGenericWrite, kOpenExisting, 0));
    CHECK(create_may_write(kGenericRead, kCreateAlways, 0));
    CHECK(create_may_write(kGenericRead, kOpenAlways, 0));
    CHECK(!create_may_write(kGenericRead, kOpenAlways, 0, /*exists=*/true));  // opens, creates nothing
    CHECK(create_may_write(kGenericWrite, kOpenAlways, 0, /*exists=*/true));
    CHECK(create_may_write(kDelete, kOpenExisting, 0));
    CHECK(create_may_write(0x02000000 /*MAXIMUM_ALLOWED*/, kOpenExisting, 0));
    CHECK(create_may_write(kGenericRead, kOpenExisting, 0x04000000 /*DELETE_ON_CLOSE*/));

    Guard g(LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\save)");
    const std::wstring save = LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\save\0\save.save)";
    // Inactive: nothing is blocked.
    CHECK(!g.block_create(save, kGenericWrite, kCreateAlways, 0));
    CHECK(!g.block_path(Op::Delete, save));
    g.set_active(true);
    CHECK(g.block_create(save, kGenericWrite, kCreateAlways, 0));
    CHECK(!g.block_create(save, kGenericRead, kOpenExisting, 0));  // the server may load the slot
    CHECK(g.block_path(Op::Delete, save));
    CHECK(g.block_path(Op::MoveTo, save));
    CHECK(!g.block_path(Op::Delete, LR"(C:\Temp\x.tmp)"));
    CHECK(!g.block_create(LR"(D:\game\cdmp.log)", kGenericWrite, kOpenAlways, 0));
    CHECK(g.blocked() == 3 && g.allowed_reads() == 1);
    g.set_active(false);
    CHECK(!g.block_path(Op::Delete, save));
}

// Session 24: [session2] save_guard=0|1|trace.
void test_save_guard_mode() {
    using namespace saveguard;
    CHECK(parse_mode("0") == Mode::Off);
    CHECK(parse_mode("1") == Mode::Block);
    CHECK(parse_mode("trace") == Mode::Trace);
    CHECK(parse_mode("TRACE") == Mode::Trace);
    CHECK(parse_mode("  Trace  ") == Mode::Trace);
    CHECK(parse_mode("trace ; sesion 24") == Mode::Trace);
    CHECK(parse_mode("trace;") == Mode::Trace);
    CHECK(parse_mode("redirect") == Mode::Redirect);
    CHECK(parse_mode("REDIRECT") == Mode::Redirect);
    CHECK(parse_mode("\tRedirect ; P8 sesion 24") == Mode::Redirect);
    CHECK(parse_mode("redirect;") == Mode::Redirect);
    CHECK(!parse_mode("redirects").has_value());
    CHECK(!parse_mode("redirec").has_value());
    // Numbers as GetPrivateProfileInt read them before: leading digits, 0 = off, any other = block.
    CHECK(parse_mode("1 ; nota") == Mode::Block);
    CHECK(parse_mode("2") == Mode::Block);
    CHECK(parse_mode("00") == Mode::Off);
    CHECK(parse_mode(" 0") == Mode::Off);
    CHECK(parse_mode("10") == Mode::Block);
    // Unknown: nullopt (config keeps block).
    CHECK(!parse_mode("").has_value());
    CHECK(!parse_mode("tracer").has_value());
    CHECK(!parse_mode("trac").has_value());
    CHECK(!parse_mode("yes").has_value());
    CHECK(!parse_mode("-1").has_value());
    CHECK(std::string(mode_name(Mode::Off)) == "off");
    CHECK(std::string(mode_name(Mode::Block)) == "block");
    CHECK(std::string(mode_name(Mode::Trace)) == "trace");
    CHECK(std::string(mode_name(Mode::Redirect)) == "redirect");
}

// Session 24: save_guard=redirect, the paths of the real autosave trace
// (backups/traza-guardado-20261011-223220.log) and the edge cases.
void test_save_redirect_path() {
    using namespace saveguard;
    const std::wstring save = LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\save)";
    const std::wstring box = LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\cdmp_save_sandbox)";
    const auto map = [&](const std::wstring& p) { return redirect_path(p, save, box); };
    // The trace's own spellings: the suffix is kept as written.
    CHECK(map(save + LR"(\1234567890\*)") == box + LR"(\1234567890\*)");
    CHECK(map(save + LR"(\1234567890\slot0_backup\*.*)") == box + LR"(\1234567890\slot0_backup\*.*)");
    CHECK(map(save + LR"(\1234567890\slot0_new\lobby.save)") == box + LR"(\1234567890\slot0_new\lobby.save)");
    CHECK(map(save + LR"(\1234567890\slot0_backup_213942844459_delete)") ==
          box + LR"(\1234567890\slot0_backup_213942844459_delete)");
    CHECK(map(save + LR"(\1234567890)") == box + LR"(\1234567890)");
    // CopyFileW's source, all in lower case: the folder matches in any case, the rest keeps its case.
    CHECK(map(LR"(c:\users\user\appdata\local\pearl abyss\cd\save\1234567890\slot0_backup\lobby.save)") ==
          box + LR"(\1234567890\slot0_backup\lobby.save)");
    CHECK(map(LR"(C:\USERS\USER\APPDATA\LOCAL\PEARL ABYSS\CD\SAVE\1234567890\Slot0\SAVE.save)") ==
          box + LR"(\1234567890\Slot0\SAVE.save)");
    // The folder itself is the sandbox root; trailing and repeated separators of the rest are kept.
    CHECK(map(save) == box);
    CHECK(map(save + L"\\") == box + L"\\");
    CHECK(map(save + L"\\\\1\\\\x") == box + L"\\\\1\\\\x");
    CHECK(map(LR"(C:\Users\user\\AppData/Local\Pearl Abyss\CD\save\1\x)") == box + LR"(\1\x)");
    CHECK(map(LR"(C:/Users/user/AppData/Local/Pearl Abyss/CD/save/1/x)") == box + L"/1/x");
    // "\\?\" and "\\.\" stay in front.
    CHECK(map(L"\\\\?\\" + save + LR"(\1\save.save)") == L"\\\\?\\" + box + LR"(\1\save.save)");
    CHECK(map(L"\\\\.\\" + save) == L"\\\\.\\" + box);
    // Not under the folder: savegame, save_x, the parent, the sandbox itself, other places.
    CHECK(!map(LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\savegame\x)"));
    CHECK(!map(LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\save_x)"));
    CHECK(!map(LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD\sav)"));
    CHECK(!map(LR"(C:\Users\user\AppData\Local\Pearl Abyss\CD)"));
    CHECK(!map(box));
    CHECK(!map(box + LR"(\1234567890\slot0\save.save)"));
    CHECK(!map(box + L"_prev"));
    CHECK(!map(LR"(D:\SteamLibrary\steamapps\common\Crimson Desert\bin64\cdmp.log)"));
    CHECK(!map(LR"(D:\Users\user\AppData\Local\Pearl Abyss\CD\save\1\x)"));
    CHECK(!map(L""));
    CHECK(!map(L"save\\1\\x"));  // relative: the caller resolves it first
    // The sandbox's own spelling: no prefix or trailing separator, '/' as '\'.
    CHECK(redirect_path(save + L"\\1", save, L"\\\\?\\E:/box/") == L"E:\\box\\1");
    // Refused folder pairs: nothing maps.
    CHECK(!redirect_path(save + L"\\1", L"", box));
    CHECK(!redirect_path(save + L"\\1", save, L""));
    CHECK(!redirect_path(save + L"\\1", save, save + L"\\box"));  // sandbox inside the save folder
    CHECK(!redirect_path(save + L"\\1", save, LR"(C:\Users\user\AppData\Local\Pearl Abyss)"));  // around it
    const Redirector r(save, box);
    CHECK(r.valid() && r.sandbox() == box && r.save_dir() == normalize(save));
    CHECK(r.under(save + L"\\1") && !r.under(box + L"\\1") && !r.under(L"C:\\save"));
    CHECK(!Redirector(save, save).valid());
}

void test_save_trace_text() {
    using namespace saveguard;
    CHECK(access_text(0) == "0x0");
    CHECK(access_text(0xC0000000) == "0xC0000000 (GENERIC_READ|GENERIC_WRITE)");
    CHECK(access_text(0x00110080) == "0x110080 (SYNCHRONIZE|DELETE|FILE_READ_ATTRIBUTES)");
    CHECK(access_text(0x80000000 | 0x01000000) == "0x81000000 (GENERIC_READ|+0x1000000)");
    CHECK(access_text(0x01000000) == "0x1000000 (+0x1000000)");
    CHECK(share_text(0x7) == "0x7 (FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)");
    CHECK(share_text(0) == "0x0");
    CHECK(file_flags_text(0x80) == "0x80 (FILE_ATTRIBUTE_NORMAL)");
    CHECK(file_flags_text(0x88000080) ==
          "0x88000080 (FILE_FLAG_WRITE_THROUGH|FILE_FLAG_SEQUENTIAL_SCAN|FILE_ATTRIBUTE_NORMAL)");
    CHECK(file_flags_text(0x10) == "0x10 (FILE_ATTRIBUTE_DIRECTORY)");
    CHECK(move_flags_text(0x3) == "0x3 (MOVEFILE_REPLACE_EXISTING|MOVEFILE_COPY_ALLOWED)");
    CHECK(move_flags_text(0x9) == "0x9 (MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)");
    CHECK(move_flags_text(0x40) == "0x40 (+0x40)");
    CHECK(disposition_text(2) == "2 (CREATE_ALWAYS)");
    CHECK(disposition_text(3) == "3 (OPEN_EXISTING)");
    CHECK(disposition_text(5) == "5 (TRUNCATE_EXISTING)");
    CHECK(disposition_text(0) == "0");
    CHECK(disposition_text(9) == "9");
}

void test_save_trace_budget() {
    using namespace saveguard;
    TraceBudget b(5, 2);
    auto l = b.take(false);  // read 1
    CHECK(l.seq == 1 && !l.last && !l.last_non_write);
    l = b.take(false);  // read 2: the last read
    CHECK(l.seq == 2 && !l.last && l.last_non_write);
    l = b.take(false);  // over the read cap: not logged, no line number used
    CHECK(l.seq == 0 && !l.last && !l.last_non_write);
    CHECK(b.take(true).seq == 3);  // writes still go
    CHECK(b.take(true).seq == 4);
    l = b.take(true);
    CHECK(l.seq == 5 && l.last);
    CHECK(b.take(true).seq == 0);  // over the total
    CHECK(b.take(false).seq == 0);
    CHECK(b.logged() == 5 && b.skipped() == 3);
    CHECK(b.total() == 5 && b.non_write_cap() == 2);
}

    static_assert(proto::kVersion == 10);
static_assert(static_cast<uint8_t>(proto::RelKind::TrocFrame) == proto::kMaxRelKind);

}  // namespace

int main() {
    test_troc_packet();
    test_troc_batch();
    test_troc_internal();
    test_packet_queue();
    test_tunnel_sender_batching();
    test_tunnel_over_reliable();
    test_troc_link();
    test_troc_link_identity();
    test_troc_link_identity_lifecycle();
    test_troc_link_guest_crash_and_return();
    test_steam_backpressure();
    test_lz_codec();
    test_compressed_batches();
    test_troc_link_compression();
    test_load_burst_latency();
    test_tick_profile();
    test_capture_file();
    test_save_guard_paths();
    test_script_parse();
    test_script_player();
    test_child_records();
    test_script_learn_child();
    test_script_learn_2661();
    test_child_script_flow();
    test_travel_script_flow();
    test_travel_script_b_flow();
    test_revive_script_flow();
    test_expect_value();
    test_generated_scripts();
    test_save_guard_policy();
    test_save_guard_mode();
    test_save_redirect_path();
    test_save_trace_text();
    test_save_trace_budget();
    if (g_failures == 0) std::printf("All option D tests passed\n");
    return g_failures == 0 ? 0 : 1;
}
