#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>


using u64 = std::uint64_t;
using u128 = unsigned __int128;

class SHA256 {
public:
    static std::array<std::uint8_t, 32> digest(const std::string &input) {
        SHA256 sha;
        sha.update(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
        return sha.final();
    }

private:
    std::array<std::uint32_t, 8> s_ = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    std::array<std::uint8_t, 64> buf_{};
    std::size_t sz_ = 0;
    std::uint64_t bits_ = 0;

    static constexpr std::uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static inline std::uint32_t rotr(std::uint32_t x, std::uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static inline std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static inline std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static inline std::uint32_t bs0(std::uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static inline std::uint32_t bs1(std::uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static inline std::uint32_t ss0(std::uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static inline std::uint32_t ss1(std::uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transform(const std::uint8_t *c) {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (std::uint32_t(c[4*i]) << 24) | (std::uint32_t(c[4*i+1]) << 16) |
                   (std::uint32_t(c[4*i+2]) << 8) | std::uint32_t(c[4*i+3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = ss1(w[i-2]) + w[i-7] + ss0(w[i-15]) + w[i-16];
        }

        auto a = s_[0], b = s_[1], cc = s_[2], d = s_[3], e = s_[4], f = s_[5], g = s_[6], h = s_[7];
        for (int i = 0; i < 64; ++i) {
            auto t1 = h + bs1(e) + ch(e, f, g) + K[i] + w[i];
            auto t2 = bs0(a) + maj(a, b, cc);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = cc;
            cc = b;
            b = a;
            a = t1 + t2;
        }

        s_[0] += a;
        s_[1] += b;
        s_[2] += cc;
        s_[3] += d;
        s_[4] += e;
        s_[5] += f;
        s_[6] += g;
        s_[7] += h;
    }

    void update(const std::uint8_t *data, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i) {
            buf_[sz_++] = data[i];
            if (sz_ == 64) {
                transform(buf_.data());
                bits_ += 512;
                sz_ = 0;
            }
        }
    }

    std::array<std::uint8_t, 32> final() {
        bits_ += sz_ * 8;
        buf_[sz_++] = 0x80;
        if (sz_ > 56) {
            while (sz_ < 64) buf_[sz_++] = 0;
            transform(buf_.data());
            sz_ = 0;
        }
        while (sz_ < 56) buf_[sz_++] = 0;
        for (int i = 7; i >= 0; --i) {
            buf_[sz_++] = std::uint8_t((bits_ >> (i*8)) & 0xff);
        }
        transform(buf_.data());
        std::array<std::uint8_t, 32> out{};
        for (int i = 0; i < 8; ++i) {
            out[4*i] = std::uint8_t((s_[i] >> 24) & 0xff);
            out[4*i+1] = std::uint8_t((s_[i] >> 16) & 0xff);
            out[4*i+2] = std::uint8_t((s_[i] >> 8) & 0xff);
            out[4*i+3] = std::uint8_t(s_[i] & 0xff);
        }
        return out;
    }
};

struct GroupParams {
    u64 p{}, q{}, g{}, h{};
};

struct Problem7Public {
    GroupParams gp;
    std::size_t n{};
    std::vector<u64> weights;
    u64 bias{};
    std::size_t rounds{};
};

struct FSRound {
    std::vector<u64> a0, a1, e0, z0, e1, z1;
    u64 t{};
    u64 z{};
};

struct FSProof {
    std::vector<u64> C;
    u64 y{};
    std::vector<FSRound> rounds;
};

using KV = std::map<std::string, std::string>;

static inline u64 mod_add(u64 a, u64 b, u64 m) {
    return (u64)((u128(a) + b) % m);
}

static inline u64 mod_sub(u64 a, u64 b, u64 m) {
    return (a >= b) ? (a - b) : (u64)(m - (b - a) % m) % m;
}

static inline u64 mod_mul(u64 a, u64 b, u64 m) {
    return (u64)((u128(a) * b) % m);
}

static u64 mod_pow(u64 base, u64 exp, u64 mod) {
    u64 res = 1 % mod;
    base %= mod;
    while (exp) {
        if (exp & 1ULL) res = mod_mul(res, base, mod);
        base = mod_mul(base, base, mod);
        exp >>= 1ULL;
    }
    return res;
}

// Computes the modular inverse using the Extended Euclidean Algorithm with signed 128-bit state to safely prevent integer underflow.
static u64 egcd_inv(u64 a, u64 mod) {
    __int128 t = 0, new_t = 1;
    __int128 r = mod, new_r = a % mod;
    while (new_r != 0) {
        __int128 q_quot = r / new_r;
        __int128 tt = t - q_quot * new_t;
        t = new_t;
        new_t = tt;
        __int128 tr = r - q_quot * new_r;
        r = new_r;
        new_r = tr;
    }
    if (r != 1) throw std::runtime_error("inverse does not exist");
    if (t < 0) t += mod;
    return (u64)t;
}

static inline u64 mod_div(u64 a, u64 b, u64 mod) {
    return mod_mul(a, egcd_inv(b, mod), mod);
}

static std::mt19937_64 &rng() {
    // std::random_device taps into the OS's cryptographically secure entropy pool (e.g., /dev/urandom)
    static std::mt19937_64 gen(std::random_device{}()); 
    return gen;
}

static u64 rand_mod(u64 q) {
    std::uniform_int_distribution<u64> dist(0, q - 1);
    return dist(rng());
}

static std::string join_u64(const std::vector<u64> &v, const std::string &sep = ",") {
    std::ostringstream oss;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) oss << sep;
        oss << v[i];
    }
    return oss.str();
}

static std::vector<u64> split_u64(const std::string &s, char sep = ',') {
    std::vector<u64> out;
    std::stringstream ss(s);
    std::string tok;
    while (std::getline(ss, tok, sep)) {
        if (!tok.empty()) out.push_back((u64)std::stoull(tok));
    }
    return out;
}

static u64 hash_to_mod_q(const std::string &s, u64 q) {
    auto d = SHA256::digest(s);
    u128 x = 0;
    for (auto b : d) {
        x = ((x << 8) | b) % q; // Safely shift and reduce byte by byte
    }
    return (u64)x;
}

static KV read_kv_file(const std::string &path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open file: " + path);
    KV kv;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        kv[line.substr(0, pos)] = line.substr(pos + 1);
    }
    return kv;
}

inline void write_kv_file(const std::string &path, const KV &kv) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot write file: " + path);
    for (const auto &p : kv) out << p.first << '=' << p.second << '\n';
}

static Problem7Public load_public(const std::string &path) {
    auto kv = read_kv_file(path);
    Problem7Public pub;
    pub.gp.p = std::stoull(kv.at("p"));
    pub.gp.q = std::stoull(kv.at("q"));
    pub.gp.g = std::stoull(kv.at("g"));
    pub.gp.h = std::stoull(kv.at("h"));
    pub.n = (std::size_t)std::stoull(kv.at("n"));
    pub.weights = split_u64(kv.at("weights"));
    pub.bias = std::stoull(kv.at("bias"));
    pub.rounds = (std::size_t)std::stoull(kv.at("rounds"));
    if (pub.weights.size() != pub.n)
        throw std::runtime_error("weights size mismatch");
    return pub;
}

static std::string context_string(const Problem7Public &pub, const std::vector<u64> &C, u64 y, std::size_t round) {
    std::ostringstream oss;
    oss << "p=" << pub.gp.p << "|q=" << pub.gp.q << "|g=" << pub.gp.g << "|h=" << pub.gp.h
        << "|n=" << pub.n << "|weights=" << join_u64(pub.weights) << "|bias=" << pub.bias
        << "|y=" << y << "|C=" << join_u64(C) << "|round=" << round;
    return oss.str();
}

// Deterministically derives cryptographic challenges via domain-separated SHA-256 for the Fiat-Shamir transform.
static u64 fs_hash_lin(const Problem7Public &pub, const std::vector<u64> &C, u64 y, std::size_t round, u64 t) {
    std::ostringstream oss;
    oss << "lin|" << context_string(pub, C, y, round) << "|t=" << t;
    return hash_to_mod_q(oss.str(), pub.gp.q);
}

// Deterministically derives cryptographic challenges via domain-separated SHA-256 for the Fiat-Shamir transform.
static u64 fs_hash_bit(const Problem7Public &pub, const std::vector<u64> &C, u64 y, std::size_t round,
                       std::size_t i, u64 a0, u64 a1) {
    std::ostringstream oss;
    oss << "bit|" << context_string(pub, C, y, round) << "|i=" << i << "|a0=" << a0 << "|a1=" << a1;
    return hash_to_mod_q(oss.str(), pub.gp.q);
}

static void send_all(int fd, const std::string &data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0)
            throw std::runtime_error("socket send failed");
        sent += (std::size_t)n;
    }
}

static std::string recv_line(int fd, std::string &buffer) {
    while (true) {
        auto pos = buffer.find('\n');
        if (pos != std::string::npos) {
            std::string line = buffer.substr(0, pos);
            buffer.erase(0, pos + 1);
            return line;
        }
        char tmp[1024];
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0)
            throw std::runtime_error("socket receive failed or connection closed");
        buffer.append(tmp, tmp + n);
    }
}

static void send_message(int fd, const KV &kv) {
    std::ostringstream oss;
    for (const auto &p : kv)
        oss << p.first << '=' << p.second << '\n';
    oss << "END\n";
    send_all(fd, oss.str());
}

static KV recv_message(int fd, std::string &buffer) {
    KV kv;
    while (true) {
        std::string line = recv_line(fd, buffer);
        if (line == "END")
            break;
        auto pos = line.find('=');
        if (pos == std::string::npos)
            continue;
        kv[line.substr(0, pos)] = line.substr(pos + 1);
    }
    return kv;
}