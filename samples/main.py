
import csv
import time

from charm.toolbox.pairinggroup import PairingGroup, GT
from ABE.ac17 import AC17CPABE


MAX_ATTRIBUTES = 100
RUNS = 10
WARMUP_RUNS = 3


def run_test(pairing_group, cpabe, n):

    # Generate attributes
    attr_list = [
        "ATTR{}".format(i)
        for i in range(1, n + 1)
    ]

    # Construct AND-only policy
    policy_str = " and ".join(attr_list)

    result = {}

    # SETUP
    start = time.perf_counter()
    pk, msk = cpabe.setup()
    result["setup_ms"] = (time.perf_counter() - start) * 1000

    # KEY GENERATION
    start = time.perf_counter()
    key = cpabe.keygen(pk, msk, attr_list)
    result["keygen_ms"] = (time.perf_counter() - start) * 1000

    # MESSAGE
    msg = pairing_group.random(GT)

    # ENCRYPTION
    start = time.perf_counter()
    ctxt = cpabe.encrypt(pk, msg, policy_str)
    result["encrypt_ms"] = (time.perf_counter() - start) * 1000

    # DECRYPTION
    start = time.perf_counter()
    recovered_msg = cpabe.decrypt(pk, ctxt, key)
    result["decrypt_ms"] = (time.perf_counter() - start) * 1000

    # TOTAL
    result["total_ms"] = (
        result["setup_ms"]
        + result["keygen_ms"]
        + result["encrypt_ms"]
        + result["decrypt_ms"]
    )

    # CORRECTNESS
    result["correct"] = (recovered_msg == msg)

    return result, policy_str

def main():

    pairing_group = PairingGroup("MNT224")
    cpabe = AC17CPABE(pairing_group, 2)

    output_file = "AND_benchmark_results.csv"

    with open(output_file, "w", newline="") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "Attributes",
            "Run",
            "Setup_ms",
            "KeyGen_ms",
            "Encrypt_ms",
            "Decrypt_ms",
            "Total_ms",
            "Correct"
        ])

        for n in range(1, MAX_ATTRIBUTES + 1):

            print("\n================================")
            print("ATTRIBUTES:", n)
            print("================================")

            # Warm-up runs (not recorded)
            for _ in range(WARMUP_RUNS):
                run_test(pairing_group, cpabe, n)

            # Measured runs
            for run in range(1, RUNS + 1):

                result, policy_str = run_test(
                    pairing_group,
                    cpabe,
                    n
                )

                writer.writerow([
                    n,
                    run,
                    result["setup_ms"],
                    result["keygen_ms"],
                    result["encrypt_ms"],
                    result["decrypt_ms"],
                    result["total_ms"],
                    result["correct"]
                ])

                csvfile.flush()

                print(
                    "Run {}/{} | Setup: {:.4f} ms | "
                    "KeyGen: {:.4f} ms | Encrypt: {:.4f} ms | "
                    "Decrypt: {:.4f} ms | Total: {:.4f} ms | "
                    "Correct: {}".format(
                        run,
                        RUNS,
                        result["setup_ms"],
                        result["keygen_ms"],
                        result["encrypt_ms"],
                        result["decrypt_ms"],
                        result["total_ms"],
                        result["correct"]
                    )
                )

                if not result["correct"]:
                    raise RuntimeError(
                        "Decryption failed for policy: "
                        + policy_str
                    )

    print("\nBenchmark completed.")
    print("Results saved to:", output_file)


if __name__ == "__main__":
    main()
