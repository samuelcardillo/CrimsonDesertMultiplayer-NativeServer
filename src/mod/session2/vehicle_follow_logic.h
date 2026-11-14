#pragma once
// vehicle_follow (vehicle_follow.h): the pure part. Build 1.0.0.3576, docs/ESTADO-3527.md "13-nov: BARCO".
//
// Each client simulates its own copy of a ship. The other player's ship is drawn from its hierarchy parent, the vehicle
// actor (type 5), which every frame gets a TransformSync request of type 7 with the local ship's pose. The vehicle
// actor's last network pose (the controller's, ~1 Hz) sits in its TransformSync at +0x550 (world vec3) / +0x55C (quat).
// vehicle_follow replaces that request's pose with one built from those network samples (interpolated, extrapolated
// past the newest for up to a second), so the ship and everything attached to it is drawn where the controller has it.

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace cdmp::session2::vfl {

struct Pose {
    double x = 0, y = 0, z = 0;
    float q[4] = {0, 0, 0, 1};
};

inline bool finite_pose(const Pose& p) {
    return std::isfinite(p.x) && std::isfinite(p.y) && std::isfinite(p.z) && std::isfinite(p.q[0]) &&
           std::isfinite(p.q[1]) && std::isfinite(p.q[2]) && std::isfinite(p.q[3]);
}
inline bool unit_quat(const float q[4]) {
    const float n = q[0] * q[0] + q[1] * q[1] + q[2] * q[2] + q[3] * q[3];
    return std::isfinite(n) && std::fabs(n - 1.0f) < 0.02f;
}
// A usable network sample: finite, not the zero of a vehicle that never got one, a unit quaternion.
inline bool usable(const Pose& p) {
    return finite_pose(p) && !(p.x == 0 && p.z == 0) && std::fabs(p.x) < 1.0e6 && std::fabs(p.z) < 1.0e6 && unit_quat(p.q);
}

inline double dist_xz(const Pose& a, const Pose& b) { return std::hypot(a.x - b.x, a.z - b.z); }

// Normalised lerp of two quaternions along the shorter arc.
inline void nlerp(const float a[4], const float b[4], double t, float out[4]) {
    const float dot = a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3];
    const float s = dot < 0 ? -1.0f : 1.0f;
    float n = 0;
    for (int i = 0; i < 4; ++i) {
        out[i] = static_cast<float>(a[i] + (s * b[i] - a[i]) * t);
        n += out[i] * out[i];
    }
    n = std::sqrt(n);
    if (n > 1e-6f)
        for (int i = 0; i < 4; ++i) out[i] /= n;
}

inline Pose lerp(const Pose& a, const Pose& b, double t) {
    Pose r;
    r.x = a.x + (b.x - a.x) * t;
    r.y = a.y + (b.y - a.y) * t;
    r.z = a.z + (b.z - a.z) * t;
    nlerp(a.q, b.q, t, r.q);
    return r;
}

// q v q^-1 for a unit quaternion (x, y, z, w): a vector of the child's frame in the parent's.
inline void rotate(const float q[4], const float v[3], double out[3]) {
    const double x = q[0], y = q[1], z = q[2], w = q[3];
    const double cx = y * v[2] - z * v[1], cy = z * v[0] - x * v[2], cz = x * v[1] - y * v[0];
    const double dx = y * cz - z * cy, dy = z * cx - x * cz, dz = x * cy - y * cx;
    out[0] = v[0] + 2 * (w * cx + dx);
    out[1] = v[1] + 2 * (w * cy + dy);
    out[2] = v[2] + 2 * (w * cz + dz);
}
// a b: the rotation b followed by a (a child's rotation b seen from the parent's frame a).
inline void mul(const float a[4], const float b[4], float out[4]) {
    const float ax = a[0], ay = a[1], az = a[2], aw = a[3], bx = b[0], by = b[1], bz = b[2], bw = b[3];
    out[0] = aw * bx + ax * bw + ay * bz - az * by;
    out[1] = aw * by - ax * bz + ay * bw + az * bx;
    out[2] = aw * bz + ax * by - ay * bx + az * bw;
    out[3] = aw * bw - ax * bx - ay * by - az * bz;
}
// The world pose of something that sits at (local_pos, local_q) on a parent with the world pose `parent`.
inline Pose attach(const Pose& parent, const float local_pos[3], const float local_q[4]) {
    double w[3];
    rotate(parent.q, local_pos, w);
    Pose r;
    r.x = parent.x + w[0];
    r.y = parent.y + w[1];
    r.z = parent.z + w[2];
    mul(parent.q, local_q, r.q);
    return r;
}

// The network samples of one vehicle, in the order they changed (t = local milliseconds of the change).
class Track {
public:
    static constexpr size_t kCap = 8;
    // Drawn this far behind the samples' arrival. The controller's character is drawn ~200-600 ms behind
    // (remote_interp's players' delay), so the ship uses about the same and extrapolates between its ~1 Hz samples
    // (the controller keeps sending them while the ship is still): at full sail (~9 m/s) a 1.2 s delay left the
    // helmsman ~8 m ahead of the wheel.
    static constexpr uint64_t kDefaultDelayMs = 300;
    static constexpr uint64_t kMaxExtrapMs = 1000;  // past the newest sample, at most this much of its velocity
    static constexpr double kTeleportM = 60.0;   // a bigger step between two samples is not interpolated

    explicit Track(uint64_t delay_ms = kDefaultDelayMs) : delay_ms_(delay_ms) {}
    void set_delay(uint64_t delay_ms) { delay_ms_ = delay_ms; }
    uint64_t delay() const { return delay_ms_; }

    // A sample read now; kept only when it differs from the newest one. True when added.
    bool push(uint64_t t_ms, const Pose& p) {
        if (!usable(p)) return false;
        if (n_) {
            const Pose& last = s_[(head_ + n_ - 1) % kCap].p;
            const bool same = std::fabs(last.x - p.x) < 1e-3 && std::fabs(last.y - p.y) < 1e-3 &&
                              std::fabs(last.z - p.z) < 1e-3 && std::fabs(last.q[0] - p.q[0]) < 1e-5f &&
                              std::fabs(last.q[1] - p.q[1]) < 1e-5f && std::fabs(last.q[2] - p.q[2]) < 1e-5f &&
                              std::fabs(last.q[3] - p.q[3]) < 1e-5f;
            if (same) return false;
            if (t_ms <= s_[(head_ + n_ - 1) % kCap].t) t_ms = s_[(head_ + n_ - 1) % kCap].t + 1;
        }
        if (n_ == kCap) {
            head_ = (head_ + 1) % kCap;
            --n_;
        }
        s_[(head_ + n_) % kCap] = {t_ms, p};
        ++n_;
        return true;
    }
    size_t size() const { return n_; }
    void clear() { n_ = head_ = 0; }

    // The pose to draw at local time now_ms (false: no sample yet).
    bool at(uint64_t now_ms, Pose* out) const {
        if (!n_) return false;
        const uint64_t t = now_ms > delay_ms_ ? now_ms - delay_ms_ : 0;
        const Sample& first = get(0);
        if (n_ == 1 || t <= first.t) {
            *out = n_ == 1 ? first.p : (t <= first.t ? first.p : get(n_ - 1).p);
            return true;
        }
        for (size_t i = 0; i + 1 < n_; ++i) {
            const Sample& a = get(i);
            const Sample& b = get(i + 1);
            if (t >= a.t && t <= b.t) {
                if (dist_xz(a.p, b.p) > kTeleportM) {
                    *out = b.p;
                    return true;
                }
                *out = lerp(a.p, b.p, static_cast<double>(t - a.t) / static_cast<double>(b.t - a.t));
                return true;
            }
        }
        // Past the newest sample: keep moving with the last segment's velocity for a short while.
        const Sample& a = get(n_ - 2);
        const Sample& b = get(n_ - 1);
        const uint64_t over = t - b.t;
        if (over > kMaxExtrapMs || dist_xz(a.p, b.p) > kTeleportM) {
            *out = b.p;
            return true;
        }
        const double k = static_cast<double>(over) / static_cast<double>(b.t - a.t);
        Pose r = b.p;
        r.x += (b.p.x - a.p.x) * k;
        r.y += (b.p.y - a.p.y) * k;
        r.z += (b.p.z - a.p.z) * k;
        *out = r;
        return true;
    }

private:
    struct Sample {
        uint64_t t;
        Pose p;
    };
    const Sample& get(size_t i) const { return s_[(head_ + i) % kCap]; }
    std::array<Sample, kCap> s_{};
    size_t n_ = 0, head_ = 0;
    uint64_t delay_ms_ = kDefaultDelayMs;
};

// A world coordinate as the game's TransformSync position argument: a float local to a 1000 m sector plus the sector.
// The caller's sector (`hint`) is kept when the local value stays within it; else the sector that truncates toward zero
// (what the game writes: -10384.7 -> sector -10, local -384.7).
inline void to_sector(double world, int16_t hint, float* local, int16_t* sector) {
    const double l = world - hint * 1000.0;
    if (std::fabs(l) < 1000.0) {
        *local = static_cast<float>(l);
        *sector = hint;
        return;
    }
    const int s = static_cast<int>(world / 1000.0);
    *sector = static_cast<int16_t>(s);
    *local = static_cast<float>(world - s * 1000.0);
}

}  // namespace cdmp::session2::vfl
