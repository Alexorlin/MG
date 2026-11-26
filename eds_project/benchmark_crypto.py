import os
import sys
import time
import json

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from client_app.core.crypto_engine import CryptoEngine


def run_crypto_benchmark() -> dict:
    """Бенчмаркінг швидкодії алгоритмів RSA-2048, RSA-4096, ECDSA P-256 та Ed25519."""
    algorithms = ["RSA-2048", "RSA-4096", "ECDSA", "Ed25519"]
    file_sizes = {
        "10 KB": 10 * 1024,
        "1 MB": 1 * 1024 * 1024,
        "10 MB": 10 * 1024 * 1024,
        "50 MB": 50 * 1024 * 1024,
    }

    keygen_runs = {"RSA-2048": 10, "RSA-4096": 5, "ECDSA": 30, "Ed25519": 30}
    sign_verify_runs = 15

    test_payloads = {label: os.urandom(size) for label, size in file_sizes.items()}

    results = {
        "key_metrics": {},
        "performance_by_size": {label: {} for label in file_sizes},
    }

    print("=" * 88)
    print(" ЕКСПЕРИМЕНТАЛЬНЕ ДОСЛІДЖЕННЯ ШВИДКОДІЇ ТА РЕСУРСОЄМНОСТІ АЛГОРИТМІВ ЕЦП")
    print("=" * 88)

    print("\n[Таблиця 1] Генерація ключів та обсяг криптографічних даних:")
    print("-" * 88)
    print(
        f"{'Алгоритм':<12} | {'Час генер. (мс)':<16} | "
        f"{'Приват. ключ (Б)':<17} | {'Публ. ключ (Б)':<15} | {'Підпис .sig (Б)':<15}"
    )
    print("-" * 88)

    key_pairs = {}
    sample_doc = test_payloads["10 KB"]

    for algo in algorithms:
        runs = keygen_runs[algo]
        t_start = time.perf_counter()
        priv_pem, pub_pem = b"", b""
        for _ in range(runs):
            priv_pem, pub_pem = CryptoEngine.generate_key_pair(algorithm=algo, password=None)
        avg_keygen_ms = ((time.perf_counter() - t_start) / runs) * 1000.0

        priv_enc_pem, _ = CryptoEngine.generate_key_pair(algorithm=algo, password="2026_Pin_Code")
        sig_sample = CryptoEngine.sign_data(sample_doc, priv_pem, password=None)
        key_pairs[algo] = (priv_pem, pub_pem)

        results["key_metrics"][algo] = {
            "keygen_ms": round(avg_keygen_ms, 3),
            "priv_pem_bytes": len(priv_pem),
            "priv_enc_pem_bytes": len(priv_enc_pem),
            "pub_pem_bytes": len(pub_pem),
            "signature_bytes": len(sig_sample),
        }

        print(
            f"{algo:<12} | {avg_keygen_ms:>14.3f}   | {len(priv_pem):>15}   | "
            f"{len(pub_pem):>13}   | {len(sig_sample):>13}"
        )

    print("\n[Таблиця 2] Час підписання та верифікації залежно від розміру документа:")
    print("-" * 88)
    print(
        f"{'Розмір файлу':<14} | {'Алгоритм':<12} | "
        f"{'Час підпису (мс)':<20} | {'Час верифікації (мс)':<22} | {'Статус'}"
    )
    print("-" * 88)

    for size_label, payload in test_payloads.items():
        for algo in algorithms:
            priv_pem, pub_pem = key_pairs[algo]

            t0 = time.perf_counter()
            sig = b""
            for _ in range(sign_verify_runs):
                sig = CryptoEngine.sign_data(payload, priv_pem, password=None)
            avg_sign_ms = ((time.perf_counter() - t0) / sign_verify_runs) * 1000.0

            t1 = time.perf_counter()
            is_valid = False
            for _ in range(sign_verify_runs):
                is_valid = CryptoEngine.verify_signature(payload, sig, pub_pem)
            avg_verify_ms = ((time.perf_counter() - t1) / sign_verify_runs) * 1000.0

            results["performance_by_size"][size_label][algo] = {
                "sign_ms": round(avg_sign_ms, 3),
                "verify_ms": round(avg_verify_ms, 3),
                "valid": is_valid,
            }

            status_str = "OK (Valid)" if is_valid else "ERROR"
            print(
                f"{size_label:<14} | {algo:<12} | {avg_sign_ms:>18.3f}   | "
                f"{avg_verify_ms:>20.3f}   | {status_str}"
            )
        print("-" * 88)

    return results


if __name__ == "__main__":
    data = run_crypto_benchmark()
    out_json = os.path.join(PROJECT_ROOT, "benchmark_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\nРезультати збережено у файл: {out_json}")
