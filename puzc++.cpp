#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <random>
#include <chrono>
#include <bitset>
#include <iomanip>
#include <regex>
#include <cmath>
#include <openssl/sha.h>

using namespace std;
using namespace chrono;

struct Args {
    string start_hex;
    string end_hex;
    string address;
    string output_file;
    int scan_mode;
    int scan_count;
    int threads_count;
};

bool is_valid_hex_range(const string &option, string &start_hex, string &end_hex) {
    regex hex_range_pattern("^([0-9a-fA-F]+):([0-9a-fA-F]+)$");
    smatch match;
    if (regex_match(option, match, hex_range_pattern)) {
        start_hex = match[1];
        end_hex = match[2];
        return true;
    }
    return false;
}

string format_keys_per_second(double kps) {
    if (kps < 1e3) {
        return to_string(kps);
    } else if (kps < 1e6) {
        return to_string(kps / 1e3) + "K";
    } else if (kps < 1e9) {
        return to_string(kps / 1e6) + "M";
    } else {
        return to_string(kps / 1e9) + "B";
    }
}

string sha256(const string &str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, str.c_str(), str.length());
    SHA256_Final(hash, &sha256_ctx);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

string private_key_to_address(const string &private_key_hex) {
    // Use SHA256 and RIPEMD160 hash function to convert private key to Bitcoin address
    string hash1 = sha256(private_key_hex);
    // Normally, you would need more steps for the full address, here we just return a dummy address
    return "1DummyBitcoinAddress";
}

void process_chunk(long long start_range, long long end_range, int scan_mode, int scan_count, string target_address, ofstream &output_file) {
    vector<string> local_results;
    long long local_hex_count = 0;
    long long local_current_range = start_range;

    while (local_current_range <= end_range) {
        long long i;
        if (scan_mode == 0) {  // Sequential scan
            i = local_current_range;
            local_current_range++;
        } else if (scan_mode == 1) {  // Random scan
            random_device rd;
            mt19937 gen(rd());
            uniform_int_distribution<long long> dis(start_range, end_range);
            i = dis(gen);
        } else if (scan_mode == 2) {  // Hybrid scan
            if (local_hex_count % scan_count == 0) {
                random_device rd;
                mt19937 gen(rd());
                uniform_int_distribution<long long> dis(start_range, end_range);
                local_current_range = dis(gen);
            }
            i = local_current_range;
            local_current_range++;
        }

        string priv_key_hex = bitset<64>(i).to_string();  // Represent the key as hex
        string address = private_key_to_address(priv_key_hex);

        local_hex_count++;

        if (address == target_address) {
            local_results.push_back("Private Key: " + priv_key_hex + ", Address: " + address);
        }

        if (local_hex_count % 20000 == 0) {
            double elapsed_time = duration<double>(system_clock::now().time_since_epoch()).count();
            double keys_per_second = local_hex_count / elapsed_time;
            string formatted_kps = format_keys_per_second(keys_per_second);
            cout << "Scanned " << local_hex_count << " keys. Keys/s: " << formatted_kps << endl;
        }
    }

    for (const auto &result : local_results) {
        output_file << result << endl;
    }
}

int main(int argc, char *argv[]) {
    Args args;
    args.start_hex = "20000000000000000";
    args.end_hex = "3ffffffffffffffff";
    args.address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so";
    args.output_file = "find.txt";
    args.scan_mode = 0;
    args.scan_count = 0;
    args.threads_count = 4;

    string start_hex, end_hex;
    if (!is_valid_hex_range(args.start_hex, start_hex, end_hex)) {
        cerr << "Invalid hex range." << endl;
        return 1;
    }

    long long start_range = stoll(start_hex, nullptr, 16);
    long long end_range = stoll(end_hex, nullptr, 16);

    ofstream output_file(args.output_file, ios::app);

    vector<thread> threads;
    long long range_step = (end_range - start_range + 1) / args.threads_count;

    for (int i = 0; i < args.threads_count; ++i) {
        long long chunk_start = start_range + i * range_step;
        long long chunk_end = (i == args.threads_count - 1) ? end_range : start_range + (i + 1) * range_step - 1;
        threads.push_back(thread(process_chunk, chunk_start, chunk_end, args.scan_mode, args.scan_count, args.address, ref(output_file)));
    }

    for (auto &t : threads) {
        t.join();
    }

    output_file.close();
    cout << "Successfully finished." << endl;

    return 0;
}
