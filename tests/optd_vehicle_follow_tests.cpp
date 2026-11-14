// vehicle_follow (src/mod/session2/vehicle_follow_logic.h): the smoothing of the controller's ~1 Hz ship samples and
// the sector form of the TransformSync position argument. Values from the 2026-11-13 test (host's ship at Vellua).

#include <cmath>
#include <cstdio>

#include "mod/session2/vehicle_follow_logic.h"

using namespace cdmp::session2::vfl;

namespace {
int g_failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); ++g_failures; } } while (0)

Pose pose(double x, double y, double z, float qy = -0.166f) {
    Pose p;
    p.x = x;
    p.y = y;
    p.z = z;
    p.q[0] = 0;
    p.q[1] = qy;
    p.q[2] = 0;
    p.q[3] = std::sqrt(1.0f - qy * qy);
    return p;
}
bool near(double a, double b, double eps = 1e-3) { return std::fabs(a - b) < eps; }

void test_usable() {
    CHECK(usable(pose(-10384.7, 350.6, -6363.0)));
    CHECK(!usable(pose(0, 350, 0)));  // a vehicle that never got a network pose
    Pose bad = pose(-10384.7, 350.6, -6363.0);
    bad.q[3] = 0.5f;
    CHECK(!usable(bad));
    bad = pose(NAN, 350.6, -6363.0);
    CHECK(!usable(bad));
}

void test_track_empty_and_single() {
    Track t;
    Pose out;
    CHECK(!t.at(5000, &out));
    CHECK(t.push(1000, pose(-10384.7, 350.6, -6363.0)));
    CHECK(!t.push(1500, pose(-10384.7, 350.6, -6363.0)));  // unchanged: not a new sample
    CHECK(t.size() == 1);
    CHECK(t.at(100000, &out) && near(out.x, -10384.7) && near(out.z, -6363.0));
}

void test_track_interpolates_behind() {
    Track t(1200);
    // The host sailing south at 6 m/s, one sample a second.
    for (int i = 0; i < 5; ++i) t.push(10000 + i * 1000, pose(-10380.0, 350.0, -6300.0 - 6.0 * i));
    Pose out;
    // Drawn 1.2 s behind: at 13700 local -> 12500 -> halfway between samples 2 and 3.
    CHECK(t.at(13700, &out));
    CHECK(near(out.z, -6315.0, 1e-6));
    // Before the first sample: the first.
    CHECK(t.at(10500, &out) && near(out.z, -6300.0));
    // Just past the newest (14000 + 1200 + 300): extrapolated 300 ms at 6 m/s.
    CHECK(t.at(15500, &out) && near(out.z, -6325.8, 1e-6));
    // Long past: held at the newest.
    CHECK(t.at(20000, &out) && near(out.z, -6324.0));
}

void test_track_default_delay_extrapolates() {
    Track t;  // 300 ms: about the delay the controller's character is drawn with
    CHECK(t.delay() == 300);
    for (int i = 0; i < 5; ++i) t.push(10000 + i * 1000, pose(-10380.0, 350.0, -6300.0 - 6.0 * i));
    Pose out;
    // 14100 local -> 13800: between the samples of 13000 and 14000.
    CHECK(t.at(14100, &out) && near(out.z, -6322.8, 1e-6));
    // 14500 local -> 14200: 200 ms past the newest, along its velocity (6 m/s).
    CHECK(t.at(14500, &out) && near(out.z, -6325.2, 1e-6));
    // More than a second past the newest (a lost sample, or none sent): held at the newest.
    CHECK(t.at(15400, &out) && near(out.z, -6324.0));
    // The switch to the next sample is continuous when the velocity holds.
    Pose before;
    CHECK(t.at(14800, &before));  // extrapolated to 14500
    t.push(14800, pose(-10380.0, 350.0, -6328.8));  // the same 6 m/s
    CHECK(t.at(14800, &out) && near(out.z, before.z, 1e-3));
    t.set_delay(1200);
    CHECK(t.delay() == 1200);
}

void test_track_teleport_not_interpolated() {
    Track t;
    t.push(1000, pose(-10124.4, 349.7, -7167.7));
    t.push(2000, pose(-10384.7, 350.6, -6363.0));  // 846 m in one step
    Pose out;
    CHECK(t.at(2700, &out) && near(out.z, -6363.0));
}

void test_track_ring_and_clock() {
    Track t;
    for (int i = 0; i < 20; ++i) t.push(1000 + i * 1000, pose(-10000.0 - i, 350.0, -6000.0));
    CHECK(t.size() == Track::kCap);
    // A sample that arrives with the same local time is moved 1 ms later, never before the newest.
    t.push(20000, pose(-10500.0, 350.0, -6000.0));
    Pose out;
    CHECK(t.at(1000000, &out) && near(out.x, -10500.0));
}

void test_rotation() {
    float a[4] = {0, -0.166f, 0, 0.98613f}, b[4] = {0, 0.166f, 0, 0.98613f}, out[4];
    nlerp(a, b, 0.5, out);
    CHECK(near(out[1], 0.0, 1e-4) && near(out[3], 1.0, 1e-4));
    // The shorter arc: -q is the same rotation.
    float c[4] = {0, 0.166f, 0, -0.98613f};
    nlerp(a, c, 0.5, out);
    CHECK(near(out[1], -0.166, 1e-3));
}

void test_to_sector() {
    float l = 0;
    int16_t s = 0;
    to_sector(-10384.7, -10, &l, &s);
    CHECK(s == -10 && near(l, -384.7, 1e-3));
    to_sector(-10384.7, -11, &l, &s);  // still inside the caller's sector
    CHECK(s == -11 && near(l, 615.3, 1e-3));
    to_sector(-6363.0, -7, &l, &s);
    CHECK(s == -7 && near(l, 637.0, 1e-3));
    to_sector(-8200.0, -6, &l, &s);  // far from the hint: truncated toward zero
    CHECK(s == -8 && near(l, -200.0, 1e-3));
}

// Live values, 2026-11-14 02:40 (host copy, 3663): the ship's vehicle and the wheel's mount hanging from it at
// (0, 2.94, 1.851); the mount's world position read from the wheel's parent frame.
void test_attach() {
    Pose ship = pose(-10372.362, 349.629, -6206.802, 0.326f);
    const float mount[3] = {0.0f, 2.94f, 1.851f}, none[4] = {0, 0, 0, 1};
    const Pose m = attach(ship, mount, none);
    CHECK(near(m.x, -10371.22, 0.08) && near(m.y, 352.57, 0.01) && near(m.z, -6205.34, 0.08));
    CHECK(near(m.q[1], 0.326, 1e-4) && near(m.q[3], ship.q[3], 1e-4));
    // the helmsman 1.17 m behind the mount, on the mount
    const float helm[3] = {0.0f, 0.0f, 1.17f};
    const Pose h = attach(m, helm, none);
    CHECK(near(std::hypot(h.x - m.x, h.z - m.z), 1.17, 1e-3) && near(h.y, m.y, 1e-4));
    // a half turn about the vertical on the parent: the wheel's local rotation (0, 1, 0, 0)
    const float half[4] = {0, 1, 0, 0}, origin[3] = {0, 0, 0};
    const Pose w = attach(pose(0.5, 0, 0.5, 0.0f), origin, half);
    CHECK(near(w.q[1], 1.0, 1e-5) && near(w.q[3], 0.0, 1e-5));
    // rotate: a quarter turn about +y takes +z to +x
    const float quarter[4] = {0, 0.70710678f, 0, 0.70710678f}, z1[3] = {0, 0, 1};
    double out[3];
    rotate(quarter, z1, out);
    CHECK(near(out[0], 1.0, 1e-5) && near(out[1], 0.0, 1e-5) && near(out[2], 0.0, 1e-5));
    float qq[4];
    mul(quarter, quarter, qq);  // two quarter turns: a half turn
    CHECK(near(qq[1], 1.0, 1e-5) && near(qq[3], 0.0, 1e-5));
}
}  // namespace

int main() {
    test_usable();
    test_track_empty_and_single();
    test_track_interpolates_behind();
    test_track_default_delay_extrapolates();
    test_track_teleport_not_interpolated();
    test_track_ring_and_clock();
    test_rotation();
    test_to_sector();
    test_attach();
    if (g_failures) {
        std::printf("%d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("vehicle_follow: all passed\n");
    return 0;
}
