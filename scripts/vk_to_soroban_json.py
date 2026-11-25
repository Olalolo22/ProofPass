#!/usr/bin/env python3
"""Convert SP1's gnark-format groth16_vk.bin into the JSON the Soroban gate constructor expects.

Output (stdout): {"alpha":"<128 hex>","beta":"<256 hex>","gamma":..., "delta":..., "ic":["<128 hex>", ...]}
Points are uncompressed big-endian, matching Soroban's Bn254G1Affine (x||y) and
Bn254G2Affine (x_c1||x_c0||y_c1||y_c0).

Usage: python3 scripts/vk_to_soroban_json.py groth16_vk.bin
"""
import json
import sys

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583


def inv(a):
    return pow(a, P - 2, P)


# --- Fp2 helpers: elements are (a0, a1) meaning a0 + a1*u, u^2 = -1 ---
def f2_add(a, b): return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)
def f2_mul(a, b): return ((a[0] * b[0] - a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P)
def f2_sq(a): return f2_mul(a, a)
def f2_neg(a): return ((-a[0]) % P, (-a[1]) % P)
def f2_inv(a):
    n = inv((a[0] * a[0] + a[1] * a[1]) % P)
    return ((a[0] * n) % P, (-a[1] * n) % P)


def f2_pow(a, e):
    r = (1, 0)
    while e:
        if e & 1:
            r = f2_mul(r, a)
        a = f2_sq(a)
        e >>= 1
    return r


def f2_sqrt(a):
    # p = 3 mod 4: complex method (Algorithm 9, Adj & Rodriguez-Henriquez)
    if a == (0, 0):
        return (0, 0)
    a1 = f2_pow(a, (P - 3) // 4)
    alpha = f2_mul(f2_sq(a1), a)
    a0 = f2_mul(f2_pow(alpha, P), alpha)  # alpha^(p+1)
    if a0 == (P - 1, 0):
        raise ValueError("not a square")
    x0 = f2_mul(a1, a)
    if alpha == (P - 1, 0):
        return f2_mul((0, 1), x0)
    b = f2_pow(f2_add((1, 0), alpha), (P - 1) // 2)
    return f2_mul(b, x0)


def fp_sqrt(a):
    r = pow(a, (P + 1) // 4, P)
    if (r * r) % P != a % P:
        raise ValueError("not a square")
    return r


FLAG_MASK = 0xC0
SMALLEST, LARGEST, INFINITY = 0x80, 0xC0, 0x40


def g1_decompress(b32):
    flag = b32[0] & FLAG_MASK
    x = int.from_bytes(bytes([b32[0] & 0x3F]) + b32[1:], "big")
    if flag == INFINITY:
        return b"\x00" * 64
    y = fp_sqrt((pow(x, 3, P) + 3) % P)
    largest = y > P - y
    if (flag == LARGEST) != largest:
        y = P - y
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def g2_decompress(b64):
    flag = b64[0] & FLAG_MASK
    x1 = int.from_bytes(bytes([b64[0] & 0x3F]) + b64[1:32], "big")  # gnark: A1 first
    x0 = int.from_bytes(b64[32:], "big")
    if flag == INFINITY:
        return b"\x00" * 128
    x = (x0, x1)
    # twist b' = 3 / (9 + u)
    bt = f2_mul((3, 0), f2_inv((9, 1)))
    y = f2_sqrt(f2_add(f2_mul(f2_sq(x), x), bt))
    ny = f2_neg(y)
    # lexicographic "largest": compare A1 first, then A0
    largest = (y[1], y[0]) > (ny[1], ny[0])
    if (flag == LARGEST) != largest:
        y = ny
    return (x1.to_bytes(32, "big") + x0.to_bytes(32, "big")
            + y[1].to_bytes(32, "big") + y[0].to_bytes(32, "big"))


def parse(data):
    o = 0
    alpha = g1_decompress(data[o:o + 32]); o += 32
    _beta_g1 = data[o:o + 32]; o += 32
    beta = g2_decompress(data[o:o + 64]); o += 64
    gamma = g2_decompress(data[o:o + 64]); o += 64
    _delta_g1 = data[o:o + 32]; o += 32
    delta = g2_decompress(data[o:o + 64]); o += 64
    n = int.from_bytes(data[o:o + 4], "big"); o += 4
    ic = []
    for _ in range(n):
        ic.append(g1_decompress(data[o:o + 32])); o += 32
    return alpha, beta, gamma, delta, ic


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "groth16_vk.bin"
    alpha, beta, gamma, delta, ic = parse(open(path, "rb").read())
    h = lambda b: b.hex()
    print(json.dumps({"alpha": h(alpha), "beta": h(beta), "gamma": h(gamma), "delta": h(delta), "ic": [h(x) for x in ic]}))


if __name__ == "__main__":
    main()
