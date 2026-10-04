#include <zkp_core.hpp>

// Aggregates the public commitments and claimed model output into a single homomorphic group element D
static u64 compute_D(const Problem7Public &pub, const std::vector<u64> &C, u64 y) {
    u64 prod = 1 % pub.gp.p;
    for (std::size_t i = 0; i < pub.n; ++i)
        prod = mod_mul(prod, mod_pow(C[i], pub.weights[i] % pub.gp.q, pub.gp.p), pub.gp.p);
    u64 exp = (pub.bias % pub.gp.q + pub.gp.q - (y % pub.gp.q)) % pub.gp.q;
    return mod_mul(prod, mod_pow(pub.gp.g, exp, pub.gp.p), pub.gp.p);
}

static FSProof deserialize_fs(const std::string &path, const Problem7Public &pub) {
    auto kv = read_kv_file(path);
    FSProof pr;
    pr.C = split_u64(kv.at("C"));
    pr.y = std::stoull(kv.at("y"));
    std::size_t rounds = (std::size_t)std::stoull(kv.at("rounds"));
    if (rounds != pub.rounds)
        throw std::runtime_error("round count mismatch");
    for (std::size_t r = 0; r < rounds; ++r) {
        FSRound row;
        row.a0 = split_u64(kv.at("a0_" + std::to_string(r)));
        row.a1 = split_u64(kv.at("a1_" + std::to_string(r)));
        row.e0 = split_u64(kv.at("e0_" + std::to_string(r)));
        row.z0 = split_u64(kv.at("z0_" + std::to_string(r)));
        row.e1 = split_u64(kv.at("e1_" + std::to_string(r)));
        row.z1 = split_u64(kv.at("z1_" + std::to_string(r)));
        row.t = std::stoull(kv.at("t_" + std::to_string(r)));
        row.z = std::stoull(kv.at("z_" + std::to_string(r)));
        pr.rounds.push_back(row);
    }
    return pr;
}

// Autonomously reconstructs Fiat-Shamir challenges and validates the zero-knowledge algebraic equations from a static transcript.
static bool verify_fs(const Problem7Public &pub, const FSProof &pr, std::string *why = nullptr) {
    if (pr.C.size() != pub.n || pr.rounds.size() != pub.rounds)
        return false;
    u64 D = compute_D(pub, pr.C, pr.y);

    std::cout << "\n[Verifier] Received FS public statement:\n";
    std::cout << "              Commitments  C = " << join_u64(pr.C) << "\n";
    std::cout << "              Model output y = " << pr.y << "\n";

    for (std::size_t round = 0; round < pub.rounds; ++round) {
        const auto &row = pr.rounds[round];

        std::cout << "\n================= Round " << round + 1 << " =================\n";
        std::cout << "[Verifier] Transcript from Prover:\n";
        std::cout << "              a0 = " << join_u64(row.a0) << "\n";
        std::cout << "              a1 = " << join_u64(row.a1) << "\n";
        std::cout << "              e0 = " << join_u64(row.e0) << "\n";
        std::cout << "              e1 = " << join_u64(row.e1) << "\n";
        std::cout << "              z0 = " << join_u64(row.z0) << "\n";
        std::cout << "              z1 = " << join_u64(row.z1) << "\n";
        std::cout << "              t = " << row.t << "\n";
        std::cout << "              z = " << row.z << "\n";

        
        // Reconstruct challenges internally to prove we don't rely on the Prover
        std::vector<u64> reconstructed_e(pub.n);
        for (std::size_t i = 0; i < pub.n; ++i) {
            reconstructed_e[i] = fs_hash_bit(pub, pr.C, pr.y, round, i, row.a0[i], row.a1[i]);
        }
        u64 c = fs_hash_lin(pub, pr.C, pr.y, round, row.t);

        // --- NON-INTERACTIVE VERIFIER LOGGING ---
        std::cout << "\n           Reconstructing challenges via SHA-256...\n";
        std::cout << "               e' = " << join_u64(reconstructed_e) << "\n";
        std::cout << "               c' = " << c << "\n\n";
        std::cout << "           Verifying algebraic commitments...\n";
        // ----------------------------------------

        for (std::size_t i = 0; i < pub.n; ++i) {
            if (mod_add(row.e0[i], row.e1[i], pub.gp.q) != reconstructed_e[i]) {
                if (why) *why = "\nFS bit challenge split failed at round " + std::to_string(round + 1) + "\n";
                return false;
            }
            u64 lhs0 = mod_pow(pub.gp.h, row.z0[i], pub.gp.p);
            u64 rhs0 = mod_mul(row.a0[i], mod_pow(pr.C[i], row.e0[i], pub.gp.p), pub.gp.p);
            if (lhs0 != rhs0) {
                if (why) *why = "\nFS branch failed at round " + std::to_string(round + 1);
                return false;
            }

            u64 cg = mod_div(pr.C[i], pub.gp.g, pub.gp.p);
            u64 lhs1 = mod_pow(pub.gp.h, row.z1[i], pub.gp.p);
            u64 rhs1 = mod_mul(row.a1[i], mod_pow(cg, row.e1[i], pub.gp.p), pub.gp.p);
            if (lhs1 != rhs1) {
                if (why)
                    *why = "\nFS branch failed at round " + std::to_string(round + 1);
                return false;
            }
        }
        
        u64 lhs = mod_pow(pub.gp.h, row.z, pub.gp.p);
        u64 rhs = mod_mul(row.t, mod_pow(D, c, pub.gp.p), pub.gp.p);
        if (lhs != rhs) {
            if (why)
                *why = "\nFS linear check failed at round " + std::to_string(round + 1);
            return false;
        }

        std::cout << "\n           Round " << round + 1 << " verified successfully.\n";
        std::cout << "===========================================\n";
    }
    return true;
}

static int start_server(int port) {
    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
        throw std::runtime_error("socket creation failed");
    int opt = 1;
    if (::setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        ::close(server_fd);
        throw std::runtime_error("setsockopt failed");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((std::uint16_t)port);
    if (::bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(server_fd);
        throw std::runtime_error("bind failed");
    }
    if (::listen(server_fd, 1) < 0) {
        ::close(server_fd);
        throw std::runtime_error("listen failed");
    }
    return server_fd;
}

// Acts as the cryptographic referee over a live TCP connection, generating unpredictable challenges and enforcing algebraic rules.
static void interactive_server(const Problem7Public &pub, int port) {
    int server_fd = start_server(port);
    std::cout << "\n[Verifier] Listening on port " << port << "...\n";

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = ::accept(server_fd, reinterpret_cast<sockaddr *>(&client_addr), &client_len);
    if (client_fd < 0) {
        ::close(server_fd);
        throw std::runtime_error("accept failed");
    }

    // --- Extract IP and Port ---
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    std::cout << "[Verifier] Prover connected from " << client_ip << ":" << client_port << "\n\n";

    std::string rx_buffer;
    KV init = recv_message(client_fd, rx_buffer);
    if (init.at("TYPE") != "INIT")
        throw std::runtime_error("expected INIT");

    std::vector<u64> C = split_u64(init.at("C"));
    u64 y = std::stoull(init.at("Y"));
    if (C.size() != pub.n)
        throw std::runtime_error("commitment size mismatch");

    std::cout << "[Verifier] Received public statement:\n";
    std::cout << "              Commitments  C = " << join_u64(C) << "\n";
    std::cout << "              Model output y = " << y << "\n";

    u64 D = compute_D(pub, C, y);

    for (std::size_t round = 0; round < pub.rounds; ++round) {
        std::cout << "\n================= Round " << round + 1 << " =================\n";

        KV commit = recv_message(client_fd, rx_buffer);
        if (commit.at("TYPE") != "COMMIT")
            throw std::runtime_error("expected COMMIT");

        std::vector<u64> a0 = split_u64(commit.at("a0"));
        std::vector<u64> a1 = split_u64(commit.at("a1"));
        u64 t = std::stoull(commit.at("t"));
        if (a0.size() != pub.n || a1.size() != pub.n)
            throw std::runtime_error("commit vector size mismatch");

        std::cout << "[Verifier] Received commitment messages:\n";
        std::cout << "              a0 = " << join_u64(a0) << "\n";
        std::cout << "              a1 = " << join_u64(a1) << "\n";
        std::cout << "              t  = " << t << "\n";

        std::vector<u64> e(pub.n);
        for (std::size_t i = 0; i < pub.n; ++i)
            e[i] = rand_mod(pub.gp.q);
        u64 c = rand_mod(pub.gp.q);

        std::cout << "\n[Verifier] Sending challenges:\n";
        std::cout << "              e = " << join_u64(e) << "\n";
        std::cout << "              c = " << c << "\n";

        KV chal;
        chal["TYPE"] = "CHALLENGE";
        chal["ROUND"] = std::to_string(round);
        chal["e"] = join_u64(e);
        chal["c"] = std::to_string(c);
        send_message(client_fd, chal);

        KV resp = recv_message(client_fd, rx_buffer);
        if (resp.at("TYPE") != "RESPONSE")
            throw std::runtime_error("expected RESPONSE");

        std::vector<u64> e0 = split_u64(resp.at("e0"));
        std::vector<u64> z0 = split_u64(resp.at("z0"));
        std::vector<u64> e1 = split_u64(resp.at("e1"));
        std::vector<u64> z1 = split_u64(resp.at("z1"));
        u64 z = std::stoull(resp.at("z"));
        if (e0.size() != pub.n || z0.size() != pub.n || e1.size() != pub.n || z1.size() != pub.n) {
            throw std::runtime_error("response vector size mismatch");
        }

        std::cout << "\n[Verifier] Received response:\n";
        std::cout << "              e0 = " << join_u64(e0) << "\n";
        std::cout << "              z0 = " << join_u64(z0) << "\n";
        std::cout << "              e1 = " << join_u64(e1) << "\n";
        std::cout << "              z1 = " << join_u64(z1) << "\n";
        std::cout << "              z  = " << z << "\n";

        for (std::size_t i = 0; i < pub.n; ++i) {
            if (mod_add(e0[i], e1[i], pub.gp.q) != e[i]) {
                std::string why = "OR challenge split failed at round " + std::to_string(round + 1);
                KV final_msg{{"TYPE", "FINAL"}, {"RESULT", "REJECT"}, {"WHY", why}};
                send_message(client_fd, final_msg);
                ::close(client_fd);
                ::close(server_fd);
                std::cout << "\n[Verifier] " << why << "\n";
                std::cout << "===========================================\n";
                std::cout << "\n[Verifier] Final result: REJECT\n";
                return;
            }
            u64 lhs0 = mod_pow(pub.gp.h, z0[i], pub.gp.p);
            u64 rhs0 = mod_mul(a0[i], mod_pow(C[i], e0[i], pub.gp.p), pub.gp.p);
            if (lhs0 != rhs0) {
                std::string why = "OR branch failed at round " + std::to_string(round + 1);
                KV final_msg{{"TYPE", "FINAL"}, {"RESULT", "REJECT"}, {"WHY", why}};
                send_message(client_fd, final_msg);
                ::close(client_fd);
                ::close(server_fd);
                std::cout << "\n[Verifier] " << why << "\n";
                std::cout << "===========================================\n";
                std::cout << "\n[Verifier] Final result: REJECT\n";
                return;
            }
            u64 cg = mod_div(C[i], pub.gp.g, pub.gp.p);
            u64 lhs1 = mod_pow(pub.gp.h, z1[i], pub.gp.p);
            u64 rhs1 = mod_mul(a1[i], mod_pow(cg, e1[i], pub.gp.p), pub.gp.p);
            if (lhs1 != rhs1) {
                std::string why = "OR branch failed at round " + std::to_string(round + 1);
                KV final_msg{{"TYPE", "FINAL"}, {"RESULT", "REJECT"}, {"WHY", why}};
                send_message(client_fd, final_msg);
                ::close(client_fd);
                ::close(server_fd);
                std::cout << "\n[Verifier] " << why << "\n";
                std::cout << "===========================================\n";
                std::cout << "\n[Verifier] Final result: REJECT\n";
                return;
            }
        }

        u64 lhs = mod_pow(pub.gp.h, z, pub.gp.p);
        u64 rhs = mod_mul(t, mod_pow(D, c, pub.gp.p), pub.gp.p);
        if (lhs != rhs) {
            std::string why = "Linear Schnorr failed at round " + std::to_string(round + 1);
            KV final_msg{{"TYPE", "FINAL"}, {"RESULT", "REJECT"}, {"WHY", why}};
            send_message(client_fd, final_msg);
            ::close(client_fd);
            ::close(server_fd);
            std::cout << "\n[Verifier] " << why << "\n";
            std::cout << "===========================================\n";
            std::cout << "\n[Verifier] Final result: REJECT\n";
            return;
        }

        std::cout << "\n[Verifier] Round " << round + 1 << " verified successfully.\n";
        std::cout << "===========================================\n";

        if (round + 1 == pub.rounds) {
            KV final_msg{{"TYPE", "FINAL"}, {"RESULT", "ACCEPT"}};
            send_message(client_fd, final_msg);
        } else {
            KV status{{"TYPE", "STATUS"}, {"ROUND", std::to_string(round)}, {"RESULT", "OK"}};
            send_message(client_fd, status);
        }
    }

    ::close(client_fd);
    ::close(server_fd);
    std::cout << "\n[Verifier] Final result: ACCEPT\n";
}

static void usage(const char *prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " interactive-server <public.txt> <port>\n"
              << "  " << prog << " verify-fs <public.txt> <fs_proof.txt>\n";
}

int main(int argc, char **argv) {
    try {
        if (argc < 2) {
            usage(argv[0]);
            return 1;
        }
        std::string cmd = argv[1];
        if (cmd == "interactive-server") {
            if (argc != 4) {
                usage(argv[0]);
                return 1;
            }
            auto pub = load_public(argv[2]);
            interactive_server(pub, std::stoi(argv[3]));
        } else if (cmd == "verify-fs") {
            if (argc != 4) {
                usage(argv[0]);
                return 1;
            }
            auto pub = load_public(argv[2]);
            auto proof = deserialize_fs(argv[3], pub);
            std::string why;
            bool ok = verify_fs(pub, proof, &why);
            std::cout << "\n" << (ok ? "[Verifier] ACCEPT" : "[Verifier] REJECT") << "\n\n";
            if (!ok)
                std::cout << why << "\n";
        } else {
            usage(argv[0]);
            return 1;
        }
        return 0;
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}