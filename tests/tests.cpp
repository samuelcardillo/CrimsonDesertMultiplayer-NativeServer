// Unit tests for the protocol and the client session state machine.
// No framework: each CHECK prints the failing line and the run exits non-zero.

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <utility>
#include <limits>
#include <vector>

#include "common/byte_ring.h"
#include "common/client_session.h"
#include "common/clock.h"
#include "common/clock_mapper.h"
#include "common/equip_state.h"
#include "common/math3d.h"
#include "common/pattern.h"
#include "common/protocol.h"
#include "common/reliable.h"
#include "common/send_gate.h"
#include "common/kick_worker.h"
#include "common/loop_health.h"
#include "common/steam_config.h"

// kick_worker.h brings windows.h, whose near/far macros clash with near() below.
#undef near
#undef far

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

proto::Packet make(proto::Body body) {
    proto::Packet p;
    p.seq = 42;
    p.send_ms = 123456;
    p.body = std::move(body);
    return p;
}

void test_roundtrip() {
    {
        auto bytes = proto::encode(make(proto::Hello{"Dayi", 7}));
        auto p = proto::decode(bytes);
        CHECK(p && p->seq == 42 && p->send_ms == 123456);
        auto* h = p ? std::get_if<proto::Hello>(&p->body) : nullptr;
        CHECK(h && h->name == "Dayi" && h->mod_build == 7);
    }
    {
        proto::PlayerState s;
        s.pos = {1.5f, -2.0f, 3.25f};
        s.rot = {0.0f, 0.7071f, 0.0f, 0.7071f};
        s.health = 254.5f;
        s.health_max = 300.0f;
        s.flags = proto::kStateSynthetic;
        s.self_key = 0xA0100066;
        s.anchor = 0xB010083F;
        s.anchor_pos = {-1.46f, 2.97f, 4.4f};
        s.anchor_rot = {0.0f, 1.0f, 0.0f, 0.0f};
        auto p = proto::decode(proto::encode(make(s)));
        auto* d = p ? std::get_if<proto::PlayerState>(&p->body) : nullptr;
        CHECK(d && d->self_key == 0xA0100066 && d->anchor == 0xB010083F);
        CHECK(d && d->anchor_pos.x == -1.46f && d->anchor_pos.y == 2.97f && d->anchor_pos.z == 4.4f);
        CHECK(d && d->anchor_rot.y == 1.0f && d->anchor_rot.w == 0.0f);
        CHECK(d && d->pos.x == 1.5f && d->pos.y == -2.0f && d->pos.z == 3.25f);
        CHECK(d && d->health == 254.5f && d->health_max == 300.0f);
        CHECK(d && d->rot.y == 0.7071f && d->rot.w == 0.7071f);
        CHECK(d && d->flags == proto::kStateSynthetic);
    }
    for (proto::Body b : {proto::Body{proto::Welcome{"x"}}, proto::Body{proto::Bye{}},
                          proto::Body{proto::Ping{9}}, proto::Body{proto::Pong{9}}}) {
        auto p = proto::decode(proto::encode(make(b)));
        CHECK(p && proto::type_of(p->body) == proto::type_of(b));
    }
}

void test_rejects_bad_input() {
    auto good = proto::encode(make(proto::Ping{1}));

    auto bad_magic = good;
    bad_magic[0] ^= 0xFF;
    CHECK(!proto::decode(bad_magic));

    auto bad_version = good;
    bad_version[4] = 99;
    CHECK(!proto::decode(bad_version));

    auto bad_type = good;
    bad_type[6] = 200;
    CHECK(!proto::decode(bad_type));

    auto truncated = good;
    truncated.pop_back();
    CHECK(!proto::decode(truncated));

    CHECK(!proto::decode(std::vector<uint8_t>(5, 0)));
    CHECK(!proto::decode(std::vector<uint8_t>(proto::kMaxPacketSize + 1, 0)));

    proto::PlayerState nan_state;
    nan_state.pos.x = std::numeric_limits<float>::quiet_NaN();
    CHECK(!proto::decode(proto::encode(make(nan_state))));

    proto::PlayerState inf_state;
    inf_state.rot.w = std::numeric_limits<float>::infinity();
    CHECK(!proto::decode(proto::encode(make(inf_state))));
    proto::PlayerState nan_anchor;
    nan_anchor.anchor_pos.y = std::numeric_limits<float>::quiet_NaN();
    CHECK(!proto::decode(proto::encode(make(nan_anchor))));

    // Long names are truncated on encode, and non-printable bytes sanitised.
    auto p = proto::decode(proto::encode(make(proto::Hello{std::string(100, 'a') , 1})));
    auto* h = p ? std::get_if<proto::Hello>(&p->body) : nullptr;
    CHECK(h && h->name.size() == proto::kMaxNameLen);
    p = proto::decode(proto::encode(make(proto::Hello{"a\nb", 1})));
    h = p ? std::get_if<proto::Hello>(&p->body) : nullptr;
    CHECK(h && h->name == "a?b");
}

struct Harness {
    std::vector<proto::Packet> sent;
    std::vector<std::string> events;
    ClientSession session{"tester", 1,
                          [this](const std::vector<uint8_t>& b) {
                              auto p = proto::decode(b);
                              if (p) sent.push_back(*p);
                          },
                          [this](const std::string& e) { events.push_back(e); }};

    void deliver(proto::Body body, uint32_t now) {
        session.on_datagram(proto::encode(make(std::move(body))), now);
    }
    size_t count(proto::Type t) const {
        size_t n = 0;
        for (auto& p : sent) n += proto::type_of(p.body) == t;
        return n;
    }
};

void test_session_handshake_and_retry() {
    Harness h;
    h.session.tick(1000);
    CHECK(h.count(proto::Type::Hello) == 1);
    h.session.tick(1500);
    CHECK(h.count(proto::Type::Hello) == 1);  // not yet time to retry
    h.session.tick(2000);
    CHECK(h.count(proto::Type::Hello) == 2);  // lost Hello is retried

    // States are not sent before the handshake completes.
    h.session.send_local_state({}, 2100);
    CHECK(h.count(proto::Type::PlayerState) == 0);

    // Nothing but Welcome is accepted while connecting.
    h.deliver(proto::PlayerState{}, 2150);
    CHECK(!h.session.remote_state());

    h.deliver(proto::Welcome{"peer"}, 2200);
    CHECK(h.session.state() == ClientSession::State::Connected);
    CHECK(h.session.peer_name() == "peer");

    h.session.send_local_state({}, 2300);
    CHECK(h.count(proto::Type::PlayerState) == 1);

    h.deliver(proto::PlayerState{{1, 2, 3}, {}, 0}, 2400);
    CHECK(h.session.remote_state() && h.session.remote_state()->pos.y == 2.0f);
}

void test_session_ping_rtt_and_timeout() {
    Harness h;
    h.session.tick(0);
    h.deliver(proto::Welcome{"peer"}, 10);
    h.session.tick(1010);
    CHECK(h.count(proto::Type::Ping) == 1);
    h.deliver(proto::Pong{1010}, 1050);
    CHECK(std::fabs(h.session.stats().rtt_ms - 40.0f) < 0.01f);

    // Peer pings us: we must answer with the same origin timestamp.
    h.deliver(proto::Ping{777}, 1100);
    CHECK(!h.sent.empty() && std::get_if<proto::Pong>(&h.sent.back().body) &&
          std::get<proto::Pong>(h.sent.back().body).origin_ms == 777);

    // Silence for kTimeoutMs drops back to Connecting and resumes Hellos.
    const size_t hellos = h.count(proto::Type::Hello);
    h.session.tick(1100 + ClientSession::kTimeoutMs);
    CHECK(h.session.state() == ClientSession::State::Connecting);
    h.session.tick(1101 + ClientSession::kTimeoutMs);
    CHECK(h.count(proto::Type::Hello) == hellos + 1);
}

void test_session_bye_and_garbage() {
    Harness h;
    h.session.tick(0);
    h.deliver(proto::Welcome{"peer"}, 10);
    h.session.on_datagram(std::vector<uint8_t>{1, 2, 3}, 20);
    CHECK(h.session.stats().rejected == 1);
    CHECK(h.session.state() == ClientSession::State::Connected);
    h.deliver(proto::Bye{}, 30);
    CHECK(h.session.state() == ClientSession::State::Connecting);
    CHECK(!h.events.empty());
}

void test_pattern() {
    CHECK(!parse_pattern(""));
    CHECK(!parse_pattern("?? ??"));  // all wildcards
    CHECK(!parse_pattern("4G"));
    CHECK(!parse_pattern("123"));
    auto p = parse_pattern("48 8b ?? ? C0");
    CHECK(p && p->size() == 5 && !p->mask[2] && !p->mask[3] && p->bytes[1] == 0x8B);

    const std::vector<uint8_t> data = {0x00, 0x48, 0x8B, 0x01, 0x02, 0xC0,
                                       0x48, 0x8B, 0xFF, 0xFF, 0xC0, 0x48};
    std::vector<size_t> hits;
    find_pattern(data, *p, hits, 10);
    CHECK(hits.size() == 2 && hits[0] == 1 && hits[1] == 6);

    hits.clear();
    find_pattern(data, *p, hits, 1);  // respects the limit
    CHECK(hits.size() == 1);

    // Leading wildcard: anchor is the first fixed byte, match at offset 0 too.
    auto lead = parse_pattern("?? 48 8B");
    hits.clear();
    find_pattern(data, *lead, hits, 10);
    CHECK(hits.size() == 2 && hits[0] == 0 && hits[1] == 5);

    // Pattern at the very end of the buffer, and longer than the buffer.
    auto tail = parse_pattern("C0 48");
    hits.clear();
    find_pattern(data, *tail, hits, 10);
    CHECK(hits.size() == 2 && hits[0] == 5 && hits[1] == 10);
    hits.clear();
    find_pattern(std::span(data).first(1), *tail, hits, 10);
    CHECK(hits.empty());
}

bool near(float a, float b) { return std::fabs(a - b) < 1e-3f; }

void test_math() {
    using math::quat_from_axes;
    auto id = quat_from_axes({1, 0, 0}, {0, 1, 0}, {0, 0, 1});
    CHECK(near(id.x, 0) && near(id.y, 0) && near(id.z, 0) && near(id.w, 1));

    // 90 degrees about Y (right-handed): X axis -> (0,0,-1), Z axis -> (1,0,0).
    auto yaw90 = quat_from_axes({0, 0, -1}, {0, 1, 0}, {1, 0, 0});
    CHECK(near(yaw90.x, 0) && near(yaw90.y, 0.70711f) && near(yaw90.z, 0) && near(yaw90.w, 0.70711f));

    // 180 degrees about Y takes the non-trace branch.
    auto yaw180 = quat_from_axes({-1, 0, 0}, {0, 1, 0}, {0, 0, -1});
    CHECK(near(std::fabs(yaw180.y), 1) && near(yaw180.w, 0));

    // Basis read live from the game (yaw about -28.6 degrees).
    proto::Vec3 gx{0.878f, 0.0f, 0.479f}, gy{0, 1, 0}, gz{-0.479f, 0.0f, 0.878f};
    CHECK(math::is_orthonormal(gx, gy, gz));
    auto g = quat_from_axes(gx, gy, gz);
    CHECK(near(g.x, 0) && near(g.z, 0) && std::fabs(g.y * g.y + g.w * g.w - 1) < 1e-3f);

    CHECK(!math::is_orthonormal({1, 0, 0}, {1, 0, 0}, {0, 0, 1}));
    CHECK(!math::is_orthonormal({2, 0, 0}, {0, 1, 0}, {0, 0, 1}));
    CHECK(!math::is_orthonormal({std::nanf(""), 0, 0}, {0, 1, 0}, {0, 0, 1}));
}

// Writes a record whose payload bytes all equal `fill`.
bool push(ByteRing& r, uint32_t len, uint8_t fill) {
    auto off = r.reserve(len);
    if (!off) return false;
    std::memset(r.at(*off), fill, len);
    std::memcpy(r.at(*off), &len, sizeof len);
    r.commit(len);
    return true;
}

void test_byte_ring() {
    std::vector<uint8_t> storage(100);
    ByteRing r(storage.data(), storage.size());
    std::vector<std::pair<uint32_t, uint8_t>> seen;
    auto drain = [&] {
        r.set_tail(r.drain(r.tail(), r.head(), [&](const uint8_t* rec, uint32_t len) {
            seen.emplace_back(len, rec[len - 1]);
        }));
    };

    CHECK(push(r, 40, 1));
    CHECK(push(r, 40, 2));
    CHECK(!push(r, 40, 3));  // only 20 bytes free
    drain();
    CHECK(seen.size() == 2 && seen[0] == std::make_pair(40u, uint8_t{1}) && seen[1].second == 2);

    // 20 bytes to the end: a 40-byte record must wrap (marker at offset 80).
    CHECK(push(r, 40, 3));
    CHECK(r.head() == 140);
    CHECK(push(r, 24, 4));
    drain();
    CHECK(seen.size() == 4 && seen[2] == std::make_pair(40u, uint8_t{3}) && seen[3].second == 4);

    // Fill exactly to the end of the ring, then wrap with < 4 bytes left.
    std::vector<uint8_t> s2(64);
    ByteRing r2(s2.data(), s2.size());
    seen.clear();
    CHECK(push(r2, 62, 7));   // 2 bytes left before the end
    r2.set_tail(r2.drain(r2.tail(), r2.head(), [&](const uint8_t* rec, uint32_t len) {
        seen.emplace_back(len, rec[len - 1]);
    }));
    CHECK(push(r2, 16, 8));   // wraps without a marker
    r2.set_tail(r2.drain(r2.tail(), r2.head(), [&](const uint8_t* rec, uint32_t len) {
        seen.emplace_back(len, rec[len - 1]);
    }));
    CHECK(seen.size() == 2 && seen[1] == std::make_pair(16u, uint8_t{8}));

    // A record larger than the whole ring is rejected.
    CHECK(!push(r2, 65, 9));

    // Long random run: interleave pushes and drains, verify order and content.
    std::vector<uint8_t> s3(4096);
    ByteRing r3(s3.data(), s3.size());
    uint32_t seed = 12345, next_fill = 0, expect_fill = 0, pushed = 0, drained = 0;
    bool order_ok = true;
    for (int i = 0; i < 20000; ++i) {
        seed = seed * 1103515245 + 12345;
        const uint32_t len = 8 + (seed >> 16) % 600;
        if (push(r3, len, static_cast<uint8_t>(next_fill))) {
            ++next_fill;
            ++pushed;
        }
        if ((seed >> 8) % 3 == 0) {
            r3.set_tail(r3.drain(r3.tail(), r3.head(), [&](const uint8_t* rec, uint32_t l) {
                if (rec[l - 1] != static_cast<uint8_t>(expect_fill)) order_ok = false;
                ++expect_fill;
                ++drained;
            }));
        }
    }
    r3.set_tail(r3.drain(r3.tail(), r3.head(), [&](const uint8_t* rec, uint32_t l) {
        if (rec[l - 1] != static_cast<uint8_t>(expect_fill)) order_ok = false;
        ++expect_fill;
        ++drained;
    }));
    CHECK(order_ok);
    CHECK(pushed > 1000 && drained == pushed);
}

void test_coop_messages() {
    {
        proto::GameEvent ev;
        ev.kind = proto::EventKind::StartAction;
        ev.payload.resize(725);
        for (size_t i = 0; i < ev.payload.size(); ++i) ev.payload[i] = static_cast<uint8_t>(i * 7);
        auto p = proto::decode(proto::encode(make(ev)));
        auto* d = p ? std::get_if<proto::GameEvent>(&p->body) : nullptr;
        CHECK(d && d->kind == proto::EventKind::StartAction && d->payload == ev.payload);
    }
    {
        // The newest event kind decodes, and so does a newer one (a newer
        // peer's): the session drops it. Kind 0 never decodes.
        proto::GameEvent ev{proto::EventKind::GuestHit, std::vector<uint8_t>(17, 0x5A)};
        auto p = proto::decode(proto::encode(make(ev)));
        auto* d = p ? std::get_if<proto::GameEvent>(&p->body) : nullptr;
        CHECK(d && d->kind == proto::EventKind::GuestHit && d->payload == ev.payload);
        ev.kind = static_cast<proto::EventKind>(proto::kMaxEventKind + 1);
        CHECK(proto::decode(proto::encode(make(ev))));
        ev.kind = static_cast<proto::EventKind>(0);
        CHECK(!proto::decode(proto::encode(make(ev))));
    }
    {
        proto::RelData rd;
        rd.msg_id = 9;
        rd.index = 2;
        rd.count = 5;
        rd.kind = proto::RelKind::Spawn;
        rd.chunk.assign(proto::kRelChunk, 0xAB);
        auto bytes = proto::encode(make(rd));
        CHECK(bytes.size() <= proto::kMaxPacketSize);
        auto p = proto::decode(bytes);
        auto* d = p ? std::get_if<proto::RelData>(&p->body) : nullptr;
        CHECK(d && d->msg_id == 9 && d->index == 2 && d->count == 5 && d->chunk == rd.chunk);
        rd.index = 5;  // index >= count
        CHECK(!proto::decode(proto::encode(make(rd))));
    }
    {
        proto::GameEvent ev;
        ev.payload.resize(10);
        auto bytes = proto::encode(make(ev));
        bytes.push_back(0);  // trailing garbage
        CHECK(!proto::decode(bytes));
    }
    {
        proto::SpawnInfo info;
        info.generation = 3;
        info.user_key = 0x90100000;
        info.player_key = 0xA0100001;
        info.body_key = 0xB0100123;
        info.pos = {-10100.5f, 617.25f, -3530.0f};
        info.rot = {0.0f, 0.38f, 0.0f, 0.925f};
        info.user.assign(12666, 0x11);
        info.body.assign(18844, 0x22);
        info.equip = {4, 1, 0, 0x10, 0xA0, 0x10, 0x24, 0, 0, 0x55, 0x66, 0x77, 0x88, 0x10, 0};
        info.horse_key = 0xB0100003;
        info.horse_pos = {-10356.95f, 620.43f, -3467.32f};
        info.horse.assign(8929, 0x33);
        auto d = proto::decode_spawn(proto::encode_spawn(info));
        CHECK(d && d->generation == 3 && d->player_key == 0xA0100001 && d->body_key == 0xB0100123);
        CHECK(d && d->pos.y == 617.25f && d->user == info.user && d->body == info.body);
        CHECK(d && d->rot.y == 0.38f && d->equip == info.equip);
        CHECK(d && d->horse_key == 0xB0100003 && d->horse_pos.z == -3467.32f && d->horse == info.horse);
        auto bytes = proto::encode_spawn(info);
        bytes.pop_back();
        CHECK(!proto::decode_spawn(bytes));
    }
}

// Two channels connected through a lossy "wire": a large message must arrive
// exactly once despite drops, and the sender must end with nothing in flight.
void test_reliable_channel() {
    std::vector<proto::Body> a_to_b, b_to_a;
    ReliableChannel a([&](proto::Body b) { a_to_b.push_back(std::move(b)); });
    ReliableChannel b([&](proto::Body x) { b_to_a.push_back(std::move(x)); });

    std::vector<uint8_t> msg(31600);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 31 + 7);
    CHECK(a.send(proto::RelKind::Spawn, msg, 0));
    CHECK(a.unacked_fragments() == 29);

    uint32_t seed = 99;
    auto drop = [&] {
        seed = seed * 1103515245 + 12345;
        return (seed >> 16) % 100 < 30;  // 30% loss both ways
    };
    int delivered = 0;
    std::vector<uint8_t> got;
    for (uint32_t t = 0; t < 20000 && (a.unacked_fragments() > 0 || delivered == 0); t += 50) {
        auto ab = std::move(a_to_b);
        a_to_b.clear();
        for (auto& body : ab) {
            if (drop()) continue;
            // Every fragment is delivered twice to exercise duplicates.
            for (int rep = 0; rep < 2; ++rep) {
                for (auto& m : b.on_data(std::get<proto::RelData>(body))) {
                    ++delivered;
                    got = m.bytes;
                    CHECK(m.kind == proto::RelKind::Spawn);
                }
            }
        }
        auto ba = std::move(b_to_a);
        b_to_a.clear();
        for (auto& body : ba) {
            if (drop()) continue;
            a.on_ack(std::get<proto::RelAck>(body));
        }
        a.tick(t);
    }
    CHECK(delivered == 1);
    CHECK(got == msg);
    CHECK(a.unacked_fragments() == 0);
    CHECK(a.resent() > 0);
    CHECK(!a.send(proto::RelKind::Spawn, std::vector<uint8_t>(proto::kMaxRelMessage + 1), 0));
}

// Messages come out in the order they were sent whatever order their
// fragments arrive in; a receiver out of room refuses (and does not
// acknowledge) new messages instead of dropping acknowledged ones; a new
// stream (the sender reset) restarts the ordering and old stragglers are
// ignored.
void test_reliable_order_and_streams() {
    std::vector<proto::Body> wire, acks;
    ReliableChannel a([&](proto::Body b) { wire.push_back(std::move(b)); });
    ReliableChannel b([&](proto::Body x) { acks.push_back(std::move(x)); });
    for (uint8_t i = 0; i < 5; ++i) CHECK(a.send(proto::RelKind::EnemyState, std::vector<uint8_t>(3000, i), 0));
    std::vector<proto::RelData> frags;
    for (auto& w : wire) frags.push_back(std::get<proto::RelData>(w));
    CHECK(frags.size() == 15);
    std::vector<uint8_t> order;
    for (auto it = frags.rbegin(); it != frags.rend(); ++it) {
        for (auto& m : b.on_data(*it)) order.push_back(m.bytes[0]);
    }
    CHECK((order == std::vector<uint8_t>{0, 1, 2, 3, 4}));

    // Room for kMaxPartials incomplete messages: the next one is refused, unacknowledged.
    acks.clear();
    ReliableChannel d([&](proto::Body x) { acks.push_back(std::move(x)); });
    size_t delivered = 0;
    for (uint32_t i = 0; i <= ReliableChannel::kMaxPartials; ++i) {
        proto::RelData half;  // the second half of a two-fragment message
        half.stream = 1001;
        half.msg_id = 1001 + i;
        half.index = 1;
        half.count = 2;
        half.chunk.assign(10, 1);
        delivered += d.on_data(half).size();
    }
    CHECK(delivered == 0);
    CHECK(d.refused() == 1);
    CHECK(acks.size() == ReliableChannel::kMaxPartials);

    // A reset sender starts a new stream: delivered from its first message on.
    ReliableChannel e([&](proto::Body x) { wire.push_back(std::move(x)); });
    ReliableChannel f([&](proto::Body) {});
    wire.clear();
    CHECK(e.send(proto::RelKind::Equip, {1}, 0));
    CHECK(e.send(proto::RelKind::Equip, {2}, 0));
    auto old_second = std::get<proto::RelData>(wire[1]);
    CHECK(f.on_data(std::get<proto::RelData>(wire[0])).size() == 1);
    e.reset();
    wire.clear();
    CHECK(e.send(proto::RelKind::Equip, {3}, 0));
    auto fresh = f.on_data(std::get<proto::RelData>(wire[0]));
    CHECK(fresh.size() == 1 && fresh[0].bytes[0] == 3);
    CHECK(f.on_data(old_second).empty());  // straggler of the old stream

    // The window: never more than kWindow fragments in flight.
    wire.clear();
    ReliableChannel g([&](proto::Body x) { wire.push_back(std::move(x)); });
    CHECK(g.send(proto::RelKind::Spawn, std::vector<uint8_t>(proto::kRelChunk * 200), 0));
    CHECK(wire.size() == ReliableChannel::kWindow);
    CHECK(g.unacked_fragments() == 200);
}

// The resend timeout follows the RTT and backs off per fragment; while the
// "can send" probe says no, nothing new goes out and nothing is resent.
void test_reliable_backoff_and_backpressure() {
    using RC = ReliableChannel;
    CHECK(RC::resend_timeout_ms(0, 0) == 250);
    CHECK(RC::resend_timeout_ms(0, 1) == 500);
    CHECK(RC::resend_timeout_ms(0, 2) == 1000);
    CHECK(RC::resend_timeout_ms(0, 3) == 2000);
    CHECK(RC::resend_timeout_ms(0, 50) == 2000);
    CHECK(RC::resend_timeout_ms(40, 0) == 250);   // a short RTT keeps the floor
    CHECK(RC::resend_timeout_ms(300, 0) == 600);  // twice the RTT
    CHECK(RC::resend_timeout_ms(300, 1) == 1200);
    CHECK(RC::resend_timeout_ms(300, 2) == 2000);
    CHECK(RC::resend_timeout_ms(2000, 0) == 2000);  // a queue-inflated RTT is capped
    CHECK(RC::resend_timeout_ms(1e9f, 0) == 2000);

    std::vector<proto::Body> wire;
    bool full = true;
    ReliableChannel c([&](proto::Body b) { wire.push_back(std::move(b)); });
    c.set_can_send([&] { return !full; });
    CHECK(c.send(proto::RelKind::Spawn, std::vector<uint8_t>(proto::kRelChunk * 10), 0));
    CHECK(wire.empty() && c.unacked_fragments() == 10 && c.held_back() == 1);
    full = false;
    c.tick(10);
    CHECK(wire.size() == 10);
    // Unacknowledged after 250 ms, but the link is full: no resend.
    full = true;
    c.tick(260);
    CHECK(wire.size() == 10 && c.resent() == 0);
    full = false;
    c.tick(261);
    CHECK(wire.size() == 20 && c.resent() == 10);
    // Second resend only after the doubled timeout (500 ms).
    c.tick(260 + 499);
    CHECK(wire.size() == 20);
    c.tick(261 + 500);
    CHECK(wire.size() == 30);
    // A measured RTT of 400 ms: the next one after 2 x 400 x 4 (capped, 2 s).
    c.set_rtt(400);
    c.tick(761 + 1999);
    CHECK(wire.size() == 30);
    c.tick(761 + 2000);
    CHECK(wire.size() == 40);
    // Acknowledged fragments stop; the window grows on request.
    for (auto& b : wire) {
        const auto& d = std::get<proto::RelData>(b);
        c.on_ack(proto::RelAck{d.msg_id, d.index});
    }
    CHECK(c.unacked_fragments() == 0);
    wire.clear();
    c.set_window(512);
    CHECK(c.window() == 512);
    CHECK(c.send(proto::RelKind::Spawn, std::vector<uint8_t>(proto::kRelChunk * 200), 3000));
    CHECK(wire.size() == 200);
    c.set_window(0);
    CHECK(c.window() == 1);
    c.set_window(1u << 20);
    CHECK(c.window() == ReliableChannel::kMaxWindow);

    // Fast resend: fragment 0 is lost, the three after it are acknowledged.
    {
        std::vector<proto::Body> w;
        ReliableChannel f([&](proto::Body b) { w.push_back(std::move(b)); });
        f.set_rtt(110);
        CHECK(f.send(proto::RelKind::Spawn, std::vector<uint8_t>(proto::kRelChunk * 5), 0));
        CHECK(w.size() == 5);
        auto ack = [&](size_t i) {
            const auto& d = std::get<proto::RelData>(w[i]);
            f.on_ack(proto::RelAck{d.msg_id, d.index});
        };
        ack(1);
        ack(2);
        f.tick(120);
        CHECK(w.size() == 5);  // only two later ones acknowledged
        ack(3);
        f.tick(100);
        CHECK(w.size() == 5);  // three, but not one RTT yet
        f.tick(120);
        CHECK(w.size() == 6 && f.fast_resent() == 1 && f.resent() == 1);  // long before the 250 ms timeout
        CHECK(std::get<proto::RelData>(w[5]).index == 0);
        f.tick(130);
        CHECK(w.size() == 6);  // once: its new transmission is newer than every ack so far
        ack(4);
        f.tick(400);  // fragment 4 was sent before the fast resend: no second fast one; the timeout (2 x 110) runs from 120
        CHECK(w.size() == 7 && f.fast_resent() == 1 && f.resent() == 2);
        // A whole stream acknowledged in order never resends.
        std::vector<proto::Body> w2;
        ReliableChannel g([&](proto::Body b) { w2.push_back(std::move(b)); });
        g.set_rtt(110);
        CHECK(g.send(proto::RelKind::Spawn, std::vector<uint8_t>(proto::kRelChunk * 8), 0));
        for (auto& b : w2) {
            const auto& d = std::get<proto::RelData>(b);
            g.on_ack(proto::RelAck{d.msg_id, d.index});
        }
        g.tick(1000);
        CHECK(w2.size() == 8 && g.resent() == 0 && g.unacked_fragments() == 0);
    }

    // Through a session: pings and other datagrams never wait; reliable ones do.
    std::vector<std::vector<uint8_t>> out;
    ClientSession s("Me", 1, [&](const std::vector<uint8_t>& b) { out.push_back(b); });
    s.tick(0);
    s.on_datagram(proto::encode(make(proto::Welcome{"peer"})), 10);
    bool congested = true;
    s.set_congestion_probe([&] { return congested; });
    CHECK(s.congested());
    out.clear();
    CHECK(s.send_reliable(proto::RelKind::Despawn, {1, 0, 0, 0}, 20));
    CHECK(out.empty() && s.reliable_pending() == 1);
    s.tick(1100);  // ping due
    CHECK(out.size() == 1 && proto::decode(out[0]) && std::holds_alternative<proto::Ping>(proto::decode(out[0])->body));
    congested = false;
    s.tick(1105);
    CHECK(out.size() == 2 && std::holds_alternative<proto::RelData>(proto::decode(out[1])->body));
    s.set_congestion_probe({});
    CHECK(!s.congested());
}

// The gate: an estimate of Steam's queue between readings, a limit of
// ~100 ms of the send rate, and a hold after a refusal.
void test_send_gate() {
    net::SendGate g;  // 100 ms, 32 KB floor, 256 KB/s assumed
    CHECK(g.limit_bytes() == 32 * 1024);
    CHECK(!g.congested(0));
    g.on_status(0, 0, 1024 * 1024);
    CHECK(g.rate() == 1024 * 1024 && g.limit_bytes() == 104857);
    g.on_sent(0, 100000);
    CHECK(!g.congested(0));
    g.on_sent(0, 10000);
    CHECK(g.congested(0) && g.estimated_pending(0) == 110000);
    CHECK(g.estimated_pending(10) == 110000 - 10485);  // drained at 1 MB/s
    CHECK(!g.congested(10));
    CHECK(g.estimated_pending(200) == 0);
    // A reading supersedes the estimate; rate 0 keeps the last rate.
    g.on_status(200, 500000, 0);
    CHECK(g.rate() == 1024 * 1024 && g.congested(200));
    CHECK(g.congested(576) && !g.congested(577));  // 500000 - 104857 drained in ~377 ms
    // A refusal: congested for the hold, then by the estimate.
    g.on_status(1000, 0, 0);
    g.on_refused(1000);
    CHECK(g.refusals() == 1);
    CHECK(g.congested(1049) && !g.congested(1050));
    // The clock wraps.
    net::SendGate w;
    w.on_status(0xFFFFFFF0u, 100000, 1024 * 1024);
    CHECK(w.estimated_pending(0x10) == 100000 - 33554);
    CHECK(w.estimated_pending(0xFFFFFFE0u) == 100000);  // earlier than the reading: nothing drained
}

// A peer with another protocol version is recognised by its Hello/Welcome
// and reported; nothing else of it decodes, and we never connect.
void test_versions() {
    auto old = proto::encode(make(proto::Hello{"Friend", 3, 77}));
    old[4] = 5;  // version field (u16 at +4)
    old[5] = 0;
    auto p = proto::decode(old);
    auto* hello = p ? std::get_if<proto::Hello>(&p->body) : nullptr;
    CHECK(p && p->version == 5 && hello && hello->name == "Friend");
    auto ping = proto::encode(make(proto::Ping{1}));
    ping[4] = 5;
    CHECK(!proto::decode(ping));

    Harness h;
    h.session.tick(0);
    h.session.on_datagram(old, 10);
    CHECK(h.session.state() == ClientSession::State::Connecting);
    CHECK(h.session.peer_problem().find("protocol 5") != std::string::npos);
    CHECK(!h.events.empty() && h.events.back().find("cannot connect") != std::string::npos);

    // Same protocol, another build: connects, with a warning.
    Harness b;
    b.session.tick(0);
    b.deliver(proto::Welcome{"Friend", 5, 0xABCDEF01}, 10);
    CHECK(b.session.state() == ClientSession::State::Connected);
    CHECK(b.session.peer_problem().find("ABCDEF01") != std::string::npos);
    // cdmp_peer's relay (build 0) is not a mismatch.
    Harness c;
    c.session.tick(0);
    c.deliver(proto::Welcome{"cdmp_peer"}, 10);
    CHECK(c.session.state() == ClientSession::State::Connected && c.session.peer_problem().empty());

    // A newer peer's event kind is dropped, not handed to the game.
    int events = 0;
    c.session.set_game_handlers([&](const proto::GameEvent&, uint32_t) { ++events; },
                                [](const ReliableChannel::Message&, uint32_t) {});
    c.deliver(proto::GameEvent{static_cast<proto::EventKind>(200), {1, 2}}, 20);
    CHECK(events == 0 && c.session.stats().unknown_kinds == 1);
}

// The session hands game events and completed reliable messages to the
// handlers, and only while connected.
void test_session_game_data() {
    std::vector<std::vector<uint8_t>> out;
    ClientSession s("Me", 1, [&](const std::vector<uint8_t>& b) { out.push_back(b); });
    int events = 0, reliables = 0;
    s.set_game_handlers([&](const proto::GameEvent&, uint32_t) { ++events; },
                        [&](const ReliableChannel::Message&, uint32_t) { ++reliables; });
    s.tick(0);
    s.send_event(proto::GameEvent{}, 0);  // not connected: dropped
    CHECK(s.stats().events_sent == 0);
    s.on_datagram(proto::encode(make(proto::Welcome{"peer"})), 10);
    CHECK(s.state() == ClientSession::State::Connected);

    out.clear();
    s.send_event(proto::GameEvent{proto::EventKind::Move, std::vector<uint8_t>(514, 1)}, 20);
    CHECK(s.send_reliable(proto::RelKind::Despawn, {1, 0, 0, 0}, 20));
    CHECK(out.size() == 2);
    // Loop everything back, like cdmp_peer's relay with a single player.
    for (auto& b : std::vector<std::vector<uint8_t>>(out)) s.on_datagram(b, 30);
    for (auto& b : std::vector<std::vector<uint8_t>>(out.begin() + 2, out.end())) s.on_datagram(b, 31);
    CHECK(events == 1);
    CHECK(reliables == 1);
    CHECK(s.reliable_pending() == 0);
}

// Remote clock 50 s ahead, transit 30-80 ms: the offset converges to
// -50000 + ~30, moves at most 1 ms per sample afterwards, and jumps only for
// big changes.
void test_clock_mapper() {
    ClockMapper m;
    CHECK(!m.offset());
    uint32_t seed = 7;
    for (uint32_t t = 0; t < 3000; t += 25) {
        seed = seed * 1103515245 + 12345;
        const uint32_t transit = 30 + (seed >> 16) % 51;
        m.add(50000 + t + transit, 100000 + t, t);  // (our clock on arrival, remote ts)
    }
    CHECK(m.offset() && *m.offset() >= -50000 + 30 && *m.offset() <= -50000 + 40);
    CHECK(m.target() && *m.target() >= -50000 + 30 && *m.target() <= -50000 + 33);
    // A faster sample lowers the target at once but the offset only by 1 ms.
    const int64_t before = *m.offset();
    m.add(50000 + 3000 + 5, 100000 + 3000, 3000);
    CHECK(*m.target() == -50000 + 5);
    CHECK(*m.offset() == before - 1);
    // Steady 40 ms transit: the fast sample expires and the offset settles on it.
    for (uint32_t t = 3025; t < 3000 + ClockMapper::kWindowMs + 2000; t += 25) {
        m.add(50000 + t + 40, 100000 + t, t);
    }
    CHECK(*m.target() == -50000 + 40);
    CHECK(*m.offset() == -50000 + 40);
    // The other game paused for 2 s: re-estimated after ~0.5 s, not 4 s.
    for (uint32_t t = 9000; t < 9000 + 25 * ClockMapper::kLateRunToReset; t += 25) {
        m.add(50000 + t + 2040, 100000 + t, t);
    }
    CHECK(*m.offset() == -50000 + 2040);
    m.reset();
    CHECK(!m.offset() && !m.target());
}

// Gear changes since the templates, with the sequences of the two-PC test of
// 5 Oct (ropa-al-desmontar.md section 2): a reloaded copy must get its
// template's items removed before the new ones go on.
void test_equip_state() {
    using Items = EquipState::Items;
    auto change = [](uint32_t serial, Items items) { return EquipState::payload(0xA0100001, serial, items); };
    // Guest: took the helmet off (slot 3), then swapped slot 4 three times.
    EquipState g;
    CHECK(g.apply(change(0x2528, {{0, 3}})));
    for (uint32_t s = 0x2529; s <= 0x252B; ++s) CHECK(g.apply(change(s, {{0xF42E4, 4}, {0, 4}})));
    CHECK((g.removals() == std::vector<uint16_t>{3, 4}));
    CHECK((g.puts() == Items{{0xF42E4, 4}}));
    CHECK(g.serial() == 0x252B);
    // Host: emptied slots 4 and 3, then put items on the empty slots.
    EquipState h;
    h.apply(change(9529, {{0, 4}}));
    h.apply(change(9530, {{0, 3}}));
    h.apply(change(9531, {{0xF4543, 3}}));
    h.apply(change(9532, {{0x1B23D, 4}}));
    CHECK((h.removals() == std::vector<uint16_t>{3, 4}));
    CHECK((h.puts() == Items{{0xF4543, 3}, {0x1B23D, 4}}));
    // The snapshot reads back to the same state (the receiver merges into it).
    EquipState back;
    CHECK(back.apply(h.snapshot(0xA0100001)));
    CHECK(back.removals() == h.removals() && back.puts() == h.puts() && back.serial() == 9532);
    const auto snap = h.snapshot(0xA0100001);
    CHECK(snap.size() == 9 + 6 * 4 && snap[0] == 4);
    // A slot that was empty at load: put on, swapped, taken off -> nothing to replay.
    EquipState e;
    e.apply(change(1, {{0x111, 7}}));
    e.apply(change(2, {{0x222, 7}, {0, 7}}));
    CHECK(e.removals().empty() && (e.puts() == Items{{0x222, 7}}));
    e.apply(change(3, {{0, 7}}));
    CHECK(e.removals().empty() && e.puts().empty());
    // Malformed payloads change nothing; the serial never goes back.
    const uint8_t bad[10] = {4};
    CHECK(!e.apply(bad, sizeof bad));
    e.apply(change(2, {{0x333, 8}}));
    CHECK(e.serial() == 3);
}

// A host (Responder) and a guest (Initiator) wired back to back: the guest
// connects, the host learns its name, and a guest restart is noticed.
void test_session_host_guest() {
    std::vector<std::vector<uint8_t>> to_host, to_guest;
    ClientSession host("Host", 1, [&](const std::vector<uint8_t>& b) { to_guest.push_back(b); }, {},
                       ClientSession::Role::Responder);
    auto make_guest = [&] {
        return ClientSession("Guest", 1, [&](const std::vector<uint8_t>& b) { to_host.push_back(b); });
    };
    ClientSession guest = make_guest();
    auto pump = [&](uint32_t now) {
        for (int i = 0; i < 4; ++i) {
            auto a = std::move(to_host);
            to_host.clear();
            for (auto& b : a) host.on_datagram(b, now);
            auto c = std::move(to_guest);
            to_guest.clear();
            for (auto& b : c) guest.on_datagram(b, now);
        }
    };
    host.tick(0);
    CHECK(to_guest.empty());  // a host never says Hello on its own
    guest.tick(0);
    pump(0);
    CHECK(host.state() == ClientSession::State::Connected && host.peer_name() == "Guest");
    CHECK(guest.state() == ClientSession::State::Connected && guest.peer_name() == "Host");
    const uint32_t epoch = host.epoch();
    CHECK(epoch == 1);

    // Duplicate Hellos (Steam delivering a queue of them) are not restarts.
    guest.disconnect(5);  // back to Connecting, same session object (same nonce)
    to_host.clear();      // the host never sees the Bye
    guest.tick(6);
    guest.tick(2000);
    for (auto& b : std::vector<std::vector<uint8_t>>(std::move(to_host))) {
        host.on_datagram(b, 50);
        host.on_datagram(b, 51);
    }
    to_host.clear();
    CHECK(host.epoch() == epoch);  // same nonce: no reset

    // The guest's game restarts: a fresh session greets the host again.
    ClientSession guest2("Guest", 1, [&](const std::vector<uint8_t>& b) { to_host.push_back(b); });
    guest2.tick(100);
    for (auto& b : std::vector<std::vector<uint8_t>>(std::move(to_host))) host.on_datagram(b, 100);
    to_host.clear();
    CHECK(host.state() == ClientSession::State::Connected && host.epoch() == epoch + 1);
}

}  // namespace

// The network thread's health (p8-hilo-red.md), on the timeline of P8 session 5.
void test_loop_health() {
    using P = LoopHealth::Phase;
    LoopHealth h;  // 250 ms
    uint64_t t = 1'000'000;
    // 1000 quiet turns: a 5 ms receive wait each, 0.2 ms of the rest.
    for (int i = 0; i < 1000; ++i) {
        h.begin(t);
        h.mark(P::Poll, t += 50);
        h.pump(t, t + 5000, 0);
        t += 5000;
        h.mark(P::Recv, t);
        h.mark(P::Session, t += 150);
        CHECK(!h.end(t));
    }
    auto w = h.take_window(t);
    CHECK(w.iterations == 1000);
    CHECK(w.slow == 0);
    CHECK(std::abs(w.mean_ms() - 5.2) < 0.01);
    CHECK(w.max_us == 5200);
    CHECK(w.max_phase == P::Recv);
    CHECK(w.max_no_pump_us == 200);  // poll + session between two receives
    CHECK(h.window_text(w).find("1000 loops, mean 5.2 ms") != std::string::npos);

    // Session 5's report: the wait-list walk held the loop 5.4 s; 17 datagrams before it.
    h.begin(t);
    h.mark(P::Poll, t += 300);
    h.pump(t, t + 1000, 17);
    t += 1000;
    h.mark(P::Recv, t);
    h.mark(P::Session, t += 100);
    h.mark(P::Report, t += 5'388'000);
    auto slow = h.end(t);
    CHECK(slow.has_value());
    if (slow) {
        CHECK(slow->worst() == P::Report);
        CHECK(slow->received == 17);
        CHECK(slow->total_us == 300 + 1000 + 100 + 5'388'000);
        CHECK(slow->no_pump_us == 100 + 5'388'000);
        const std::string text = h.slow_text(*slow);
        CHECK(text.find("one loop took 5389.4 ms (> 250 ms; mostly 5 s report)") == 0);
        CHECK(text.find("receive 1.0 ms (17 datagrams)") != std::string::npos);
        CHECK(text.find("no receive for 5388.1 ms") != std::string::npos);
    }
    // The next turn reads Steam again: the gap ends there and shows in the window.
    h.begin(t);
    t += 20;
    h.pump(t, t + 5000, 300);
    t += 5000;
    h.mark(P::Recv, t);
    CHECK(!h.end(t));
    w = h.take_window(t);
    CHECK(w.iterations == 2);
    CHECK(w.slow == 1);
    CHECK(h.slow_total() == 1);
    CHECK(w.max_phase == P::Report);
    CHECK(w.max_no_pump_us == 100 + 5'388'000 + 20);
    CHECK(w.received == 317);
    CHECK(h.window_text(w).find("slow (>250 ms) 1 (1 in all)") != std::string::npos);
    // A loop stuck right now shows up at the report even before its turn ends.
    h.begin(t);
    h.pump(t, t + 10, 0);
    t += 10;
    w = h.take_window(t + 900'000);
    CHECK(w.max_no_pump_us == 900'000);
    // Marks and ends outside a turn are ignored.
    LoopHealth idle;
    idle.mark(P::Poll, 5);
    CHECK(!idle.end(10));
    CHECK(idle.take_window(20).iterations == 0);
}

// The guest's diagnostics thread: kick() never waits for the job (session 5:
// the job took 4-8 s), and the job runs on its own when nobody kicks.
void test_kick_worker() {
    std::atomic<int> runs{0};
    std::atomic<bool> busy{false};
    KickWorker w;
    KickWorker::Config c;
    c.period_ms = 60;
    c.min_gap_ms = 0;
    CHECK(w.start(
        [&] {
            busy = true;
            Sleep(300);  // a slow walk
            ++runs;
            busy = false;
        },
        c));
    // Wait for the first (timed) run to be in progress.
    for (int i = 0; i < 200 && !busy; ++i) Sleep(5);
    CHECK(busy.load());
    uint64_t worst_us = 0;
    for (int i = 0; i < 100; ++i) {
        const uint64_t t0 = now_us();
        w.kick();
        worst_us = std::max(worst_us, now_us() - t0);
    }
    CHECK(worst_us < 20'000);  // a SetEvent, not the 300 ms job
    CHECK(w.kicks() == 100);
    for (int i = 0; i < 400 && runs.load() < 2; ++i) Sleep(5);
    CHECK(runs.load() >= 2);  // 100 kicks while busy fold into one more run
    CHECK(w.timed_runs() >= 1);
    w.stop();
    const int after = runs.load();
    Sleep(150);
    CHECK(runs.load() == after);
    // Runs never come closer than min_gap_ms.
    std::atomic<int> quick{0};
    KickWorker g;
    KickWorker::Config gc;
    gc.period_ms = 10'000;
    gc.min_gap_ms = 1'000;
    CHECK(g.start([&] { ++quick; }, gc));
    g.kick();
    for (int i = 0; i < 200 && quick.load() < 1; ++i) Sleep(5);
    for (int i = 0; i < 5; ++i) {
        g.kick();
        Sleep(20);
    }
    CHECK(quick.load() == 1);
    g.stop();
    // kick() before start() does nothing and does not crash.
    KickWorker none;
    none.kick();
    CHECK(none.runs() == 0);
}

// Steam's config values by name (steam_config.h).
void test_steam_config_lookup() {
    struct Fake {
        std::vector<std::pair<int32_t, const char*>> table;
        mutable int calls = 0;
        const char* operator()(int32_t id) const {
            ++calls;
            for (const auto& [i, n] : table) {
                if (i == id) return n;
            }
            return nullptr;
        }
    };
    using namespace net::steam_cfg;
    Fake sdk{{{kSendBufferSize, "SendBufferSize"}, {kRecvBufferSize, "RecvBufferSize"},
              {kRecvBufferMessages, "RecvBufferMessages"}, {kSendRateMin, "SendRateMin"}}};
    CHECK(net::find_config_id(sdk, kRecvBufferSize, "RecvBufferSize") == kRecvBufferSize);
    CHECK(sdk.calls == 1);  // the expected id answers at once
    CHECK(net::find_config_id(sdk, kRecvBufferMessages, "RecvBufferMessages") == kRecvBufferMessages);
    // Another client with other ids: found by name.
    Fake moved{{{60, "RecvBufferSize"}, {kRecvBufferSize, "SomethingElse"}}};
    CHECK(net::find_config_id(moved, kRecvBufferSize, "RecvBufferSize") == 60);
    // Not known at all: -1, nothing is set.
    Fake old{{{kSendBufferSize, "SendBufferSize"}}};
    CHECK(net::find_config_id(old, kRecvBufferSize, "RecvBufferSize") == -1);
    CHECK(old.calls == kMaxScannedId);  // the guess + every other id once
    // No prefix matches: "RecvBuffer" is not "RecvBufferSize".
    Fake prefix{{{kRecvBufferSize, "RecvBuffer"}}};
    CHECK(net::find_config_id(prefix, kRecvBufferSize, "RecvBufferSize") == -1);
}

int main() {
    test_pattern();
    test_byte_ring();
    test_math();
    test_roundtrip();
    test_rejects_bad_input();
    test_session_handshake_and_retry();
    test_session_ping_rtt_and_timeout();
    test_session_bye_and_garbage();
    test_coop_messages();
    test_reliable_channel();
    test_reliable_order_and_streams();
    test_reliable_backoff_and_backpressure();
    test_send_gate();
    test_versions();
    test_session_game_data();
    test_clock_mapper();
    test_equip_state();
    test_session_host_guest();
    test_loop_health();
    test_kick_worker();
    test_steam_config_lookup();
    if (g_failures == 0) std::printf("All tests passed\n");
    return g_failures == 0 ? 0 : 1;
}
