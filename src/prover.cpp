#include <zkp_core.hpp>

struct Problem7Witness {
    std::vector<u64> x, r;
};

struct CommitOutput {
    std::vector<u64> C;
    u64 y{};
};

static Problem7Witness load_witness(const std::string &path, std::size_t n) {
    auto kv = read_kv_file(path);
    Problem7Witness wit;
    wit.x = split_u64(kv.at("x"));
    wit.r = split_u64(kv.at("r"));
    if (wit.x.size() != n || wit.r.size() != n) throw std::runtime_error("witness size mismatch");
    // for (u64 bit : wit.x) {
    //     if (bit != 0 && bit != 1) throw std::runtime_error("x must be binary");
    // }
    return wit;
}

static u64 commit_value(const GroupParams &gp, u64 x, u64 r) {
    return mod_mul(mod_pow(gp.g, x, gp.p), mod_pow(gp.h, r, gp.p), gp.p);
}

static u64 compute_y(const Problem7Public &pub, const Problem7Witness &wit) {
    u64 sum = pub.bias % pub.gp.q;
    for (std::size_t i = 0; i < pub.n; ++i) {
        sum = mod_add(sum, mod_mul(pub.weights[i] % pub.gp.q, wit.x[i] % pub.gp.q, pub.gp.q), pub.gp.q);
    }
    return sum;
}

static u64 compute_rho(const Problem7Public &pub, const Problem7Witness &wit) {
    u64 rho = 0;
    for (std::size_t i = 0; i < pub.n; ++i) {
        rho = mod_add(rho, mod_mul(pub.weights[i] % pub.gp.q, wit.r[i] % pub.gp.q, pub.gp.q), pub.gp.q);
    }
    return rho;
}

// Generates perfectly hiding Pedersen commitments for the binary inputs and computes the public linear model output y.
static CommitOutput make_commitments(const Problem7Public &pub, const Problem7Witness &wit) {
    CommitOutput co;
    co.C.resize(pub.n);
    for (std::size_t i = 0; i < pub.n; ++i) {
        co.C[i] = commit_value(pub.gp, wit.x[i], wit.r[i]);
    }
    co.y = compute_y(pub, wit);
    return co;
}

static KV serialize_fs(const FSProof &pr, const Problem7Public &pub) {
    KV kv;
    kv["C"] = join_u64(pr.C);
    kv["y"] = std::to_string(pr.y);
    kv["rounds"] = std::to_string(pub.rounds);
    for (std::size_t r = 0; r < pub.rounds; ++r) {
        kv["a0_" + std::to_string(r)] = join_u64(pr.rounds[r].a0);
        kv["a1_" + std::to_string(r)] = join_u64(pr.rounds[r].a1);
        kv["e0_" + std::to_string(r)] = join_u64(pr.rounds[r].e0);
        kv["z0_" + std::to_string(r)] = join_u64(pr.rounds[r].z0);
        kv["e1_" + std::to_string(r)] = join_u64(pr.rounds[r].e1);
        kv["z1_" + std::to_string(r)] = join_u64(pr.rounds[r].z1);
        kv["t_" + std::to_string(r)] = std::to_string(pr.rounds[r].t);
        kv["z_" + std::to_string(r)] = std::to_string(pr.rounds[r].z);
    }
    return kv;
}

// Generates a non-interactive zero-knowledge transcript using the Fiat-Shamir heuristic to internally derive challenges.
static FSProof prove_fs(const Problem7Public &pub, const Problem7Witness &wit) {
    FSProof pr;
    auto co = make_commitments(pub, wit);
    pr.C = co.C;
    pr.y = co.y;
    u64 rho = compute_rho(pub, wit);

    std::cout << "\n[Prover] Generated public statement:\n";
    std::cout << "            Commitments  C = " << join_u64(pr.C) << "\n";
    std::cout << "            Model output y = " << pr.y << "\n";

    for (std::size_t round = 0; round < pub.rounds; ++round) {
        FSRound row;
        row.a0.resize(pub.n);
        row.a1.resize(pub.n);
        row.e0.resize(pub.n);
        row.z0.resize(pub.n);
        row.e1.resize(pub.n);
        row.z1.resize(pub.n);

        std::vector<u64> sim_e(pub.n), sim_z(pub.n), real_s(pub.n);
        for (std::size_t i = 0; i < pub.n; ++i) {
            sim_e[i] = rand_mod(pub.gp.q);
            sim_z[i] = rand_mod(pub.gp.q);
            real_s[i] = rand_mod(pub.gp.q);
            if (wit.x[i] == 0) {
                row.a0[i] = mod_pow(pub.gp.h, real_s[i], pub.gp.p);
                u64 cg = mod_div(pr.C[i], pub.gp.g, pub.gp.p);
                row.a1[i] = mod_mul(mod_pow(pub.gp.h, sim_z[i], pub.gp.p),
                                    egcd_inv(mod_pow(cg, sim_e[i], pub.gp.p), pub.gp.p), pub.gp.p);
            } else {
                row.a1[i] = mod_pow(pub.gp.h, real_s[i], pub.gp.p);
                row.a0[i] = mod_mul(mod_pow(pub.gp.h, sim_z[i], pub.gp.p),
                                    egcd_inv(mod_pow(pr.C[i], sim_e[i], pub.gp.p), pub.gp.p), pub.gp.p);
            }
        }

        u64 s = rand_mod(pub.gp.q);
        row.t = mod_pow(pub.gp.h, s, pub.gp.p);

        std::vector<u64> e(pub.n);
        for (std::size_t i = 0; i < pub.n; ++i) {
            e[i] = fs_hash_bit(pub, pr.C, pr.y, round, i, row.a0[i], row.a1[i]);
        }
        u64 c = fs_hash_lin(pub, pr.C, pr.y, round, row.t);

        for (std::size_t i = 0; i < pub.n; ++i) {
            if (wit.x[i] == 0) {
                row.e1[i] = sim_e[i];
                row.z1[i] = sim_z[i];
                row.e0[i] = mod_sub(e[i], row.e1[i], pub.gp.q);
                row.z0[i] = mod_add(real_s[i], mod_mul(row.e0[i], wit.r[i], pub.gp.q), pub.gp.q);
            } else {
                row.e0[i] = sim_e[i];
                row.z0[i] = sim_z[i];
                row.e1[i] = mod_sub(e[i], row.e0[i], pub.gp.q);
                row.z1[i] = mod_add(real_s[i], mod_mul(row.e1[i], wit.r[i], pub.gp.q), pub.gp.q);
            }
        }

        row.z = mod_add(s, mod_mul(c, rho, pub.gp.q), pub.gp.q);

        // --- NON-INTERACTIVE PROVER LOGGING ---
        std::cout << "\n================= Round " << round + 1 << " =================\n";
        std::cout << "[Prover] Deterministically derived challenges via SHA-256:\n";
        std::cout << "            e = " << join_u64(e) << "\n";
        std::cout << "            c = " << c << "\n\n";
        std::cout << "         Packing transcript for Verifier:\n";
        std::cout << "            a0 = " << join_u64(row.a0) << "\n";
        std::cout << "            a1 = " << join_u64(row.a1) << "\n";
        std::cout << "            e0 = " << join_u64(row.e0) << "\n";
        std::cout << "            e1 = " << join_u64(row.e1) << "\n";
        std::cout << "            z0 = " << join_u64(row.z0) << "\n";
        std::cout << "            z1 = " << join_u64(row.z1) << "\n";
        std::cout << "            t  = " << row.t << "\n";
        std::cout << "            z  = " << row.z << "\n";
        std::cout << "===========================================\n";

        pr.rounds.push_back(row);
    }

    return pr;
}

static int connect_to_server(const std::string &host, int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket creation failed");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((std::uint16_t)port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        throw std::runtime_error("invalid server address");
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        throw std::runtime_error("connect failed");
    }
    return fd;
}

// Executes the interactive TCP prover utilizing the OR-proof and linear Schnorr simulation.
static void interactive_client(const Problem7Public &pub, const Problem7Witness &wit,
                               const std::string &host, int port) {
    int fd = connect_to_server(host, port);
    std::string rx_buffer;

    auto co = make_commitments(pub, wit);
    u64 rho = compute_rho(pub, wit);

    std::cout << "\n[Prover] Connected to Verifier at " << host << ":" << port << "\n\n";
    std::cout << "[Prover] Sending public statement:\n";
    std::cout << "            Commitments  C = " << join_u64(co.C) << "\n";
    std::cout << "            Model output y = " << co.y << "\n";

    KV init_msg;
    init_msg["TYPE"] = "INIT";
    init_msg["N"] = std::to_string(pub.n);
    init_msg["ROUNDS"] = std::to_string(pub.rounds);
    init_msg["C"] = join_u64(co.C);
    init_msg["Y"] = std::to_string(co.y);
    send_message(fd, init_msg);

    for (std::size_t round = 0; round < pub.rounds; ++round) {
        std::cout << "\n================= Round " << round + 1 << " =================\n";

        std::vector<u64> sim_e(pub.n), sim_z(pub.n), real_s(pub.n), a0(pub.n), a1(pub.n);
        for (std::size_t i = 0; i < pub.n; ++i) {
            sim_e[i] = rand_mod(pub.gp.q);
            sim_z[i] = rand_mod(pub.gp.q);
            real_s[i] = rand_mod(pub.gp.q);

            if (wit.x[i] == 0) {
                a0[i] = mod_pow(pub.gp.h, real_s[i], pub.gp.p);
                u64 cg = mod_div(co.C[i], pub.gp.g, pub.gp.p);
                a1[i] = mod_mul(mod_pow(pub.gp.h, sim_z[i], pub.gp.p),
                                egcd_inv(mod_pow(cg, sim_e[i], pub.gp.p), pub.gp.p), pub.gp.p);
            } else {
                a1[i] = mod_pow(pub.gp.h, real_s[i], pub.gp.p);
                a0[i] = mod_mul(mod_pow(pub.gp.h, sim_z[i], pub.gp.p),
                                egcd_inv(mod_pow(co.C[i], sim_e[i], pub.gp.p), pub.gp.p), pub.gp.p);
            }
        }

        u64 s = rand_mod(pub.gp.q);
        u64 t = mod_pow(pub.gp.h, s, pub.gp.p);

        std::cout << "[Prover] Sending commitment messages:\n";
        std::cout << "            a0 = " << join_u64(a0) << "\n";
        std::cout << "            a1 = " << join_u64(a1) << "\n";
        std::cout << "            t  = " << t << "\n";

        KV commit_msg;
        commit_msg["TYPE"] = "COMMIT";
        commit_msg["ROUND"] = std::to_string(round);
        commit_msg["a0"] = join_u64(a0);
        commit_msg["a1"] = join_u64(a1);
        commit_msg["t"] = std::to_string(t);
        send_message(fd, commit_msg);

        KV chal_msg = recv_message(fd, rx_buffer);
        if (chal_msg.at("TYPE") != "CHALLENGE") throw std::runtime_error("expected CHALLENGE");

        std::vector<u64> e = split_u64(chal_msg.at("e"));
        u64 c = std::stoull(chal_msg.at("c"));
        if (e.size() != pub.n) throw std::runtime_error("challenge vector size mismatch");

        std::cout << "\n[Prover] Received challenges from verifier:\n";
        std::cout << "            e = " << join_u64(e) << "\n";
        std::cout << "            c = " << c << "\n";

        std::vector<u64> e0(pub.n), z0(pub.n), e1(pub.n), z1(pub.n);
        for (std::size_t i = 0; i < pub.n; ++i) {
            if (wit.x[i] == 0) {
                e1[i] = sim_e[i];
                z1[i] = sim_z[i];
                e0[i] = mod_sub(e[i], e1[i], pub.gp.q);
                z0[i] = mod_add(real_s[i], mod_mul(e0[i], wit.r[i], pub.gp.q), pub.gp.q);
            } else {
                e0[i] = sim_e[i];
                z0[i] = sim_z[i];
                e1[i] = mod_sub(e[i], e0[i], pub.gp.q);
                z1[i] = mod_add(real_s[i], mod_mul(e1[i], wit.r[i], pub.gp.q), pub.gp.q);
            }
        }
        u64 z = mod_add(s, mod_mul(c, rho, pub.gp.q), pub.gp.q);

        std::cout << "\n[Prover] Sending response:\n";
        std::cout << "            e0 = " << join_u64(e0) << "\n";
        std::cout << "            z0 = " << join_u64(z0) << "\n";
        std::cout << "            e1 = " << join_u64(e1) << "\n";
        std::cout << "            z1 = " << join_u64(z1) << "\n";
        std::cout << "            z  = " << z << "\n";

        KV resp_msg;
        resp_msg["TYPE"] = "RESPONSE";
        resp_msg["ROUND"] = std::to_string(round);
        resp_msg["e0"] = join_u64(e0);
        resp_msg["z0"] = join_u64(z0);
        resp_msg["e1"] = join_u64(e1);
        resp_msg["z1"] = join_u64(z1);
        resp_msg["z"] = std::to_string(z);
        send_message(fd, resp_msg);

        KV status = recv_message(fd, rx_buffer);
        if (status.at("TYPE") == "FINAL") {
            if (!status.count("WHY")){
                std::cout << "\n[Prover] Verifier status for round " << round + 1 << ": " << "OK" << "\n";
                std::cout << "===========================================\n";
            }
            else{
                std::cout << "\n         " << status.at("WHY") << "\n";
                std::cout << "===========================================\n";
            }
            std::cout << "\n[Prover] Final Verifier result: " << status.at("RESULT") << "\n";
            if (status.count("WHY")) std::cout << "[Prover] Reason: " << status.at("WHY") << "\n";
            ::close(fd);
            return;
        }
        if (status.at("TYPE") != "STATUS") throw std::runtime_error("expected STATUS");
        
        if (!status.count("WHY")){
            std::cout << "\n[Prover] Verifier status for round " << round + 1 << ": " << status.at("RESULT") << "\n";
            std::cout << "===========================================\n";
        }
    }

    KV final_msg = recv_message(fd, rx_buffer);
    if (final_msg.at("TYPE") != "FINAL") throw std::runtime_error("expected FINAL");

    std::cout << "\n[Prover] Final Verifier result: " << final_msg.at("RESULT") << "\n";
    if (final_msg.count("WHY")) std::cout << "[Prover] Reason: " << final_msg.at("WHY") << "\n";

    ::close(fd);
}

static void usage(const char *prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " interactive-client <public.txt> <witness.txt> <server_ip> <port>\n"
              << "  " << prog << " prove-fs <public.txt> <witness.txt> <fs_proof.txt>\n";
}

int main(int argc, char **argv) {
    try {
        if (argc < 2) {
            usage(argv[0]);
            return 1;
        }
        std::string cmd = argv[1];

        if (cmd == "interactive-client") {
            if (argc != 6) {
                usage(argv[0]);
                return 1;
            }
            auto pub = load_public(argv[2]);
            auto wit = load_witness(argv[3], pub.n);
            interactive_client(pub, wit, argv[4], std::stoi(argv[5]));
        } 
        else if (cmd == "prove-fs") {
            if (argc != 5) {
                usage(argv[0]);
                return 1;
            }
            auto pub = load_public(argv[2]);
            auto wit = load_witness(argv[3], pub.n);
            auto pr = prove_fs(pub, wit);
            write_kv_file(argv[4], serialize_fs(pr, pub));
            std::cout << "\nWrote Fiat-Shamir proof to " << argv[4] << "\n\n";
        } 
        else {
            usage(argv[0]);
            return 1;
        }

        return 0;
    } 
    catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}