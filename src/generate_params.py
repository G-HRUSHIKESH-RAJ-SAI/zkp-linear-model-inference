import argparse
import random
import sys

# Custom Miller-Rabin Primality Test
def is_prime(n, k=40):
    """Executes a probabilistic Miller-Rabin primality test (k=40)
      to guarantee prime generation without external libraries."""
    
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Write n-1 as d * 2^r
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False # Composite
            
    return True # Probably prime

def generate_subgroup_params(bits):
    """Hunts for a valid cyclic subgroup by deriving a p and q that
      strictly satisfy p = n*q + 1 within 64-bit hardware boundaries."""

    print(f"[*] Hunting for a strictly {bits}-bit prime q...")
    # Force q to be exactly 'bits' in length
    min_val = 1 << (bits - 1)
    max_val = (1 << bits) - 1
    
    # Strict 64-bit limit for C++ uint64_t compatibility
    MAX_P = (1 << 64) - 1

    while True:
        q = random.randrange(min_val, max_val)
        if not is_prime(q): continue
        
        # Find p = n * q + 1
        for n in range(2, 500, 2):
            p = n * q + 1

            if p > MAX_P:
                break # Move on to a new q, this p is too big for C++

            if is_prime(p):
                print(f"[*] Found primes! q = {q}, p = {p} (where n = {n})")
                
                def get_generator():
                    while True:
                        r = random.randint(2, p - 2)
                        gen = pow(r, (p - 1) // q, p)
                        if gen != 1:
                            return gen
                
                g = get_generator()
                h = get_generator()
                while g == h:
                    h = get_generator()
                    
                return p, q, g, h

def main():
    parser = argparse.ArgumentParser(description="ZKP Cryptographic Parameter Generator")
    parser.add_argument("--public", type=str, default="public.txt", help="Output public file name")
    parser.add_argument("--witness", type=str, default="witness.txt", help="Output witness file name")
    parser.add_argument("--rounds", type=int, default=5, help="Number of protocol rounds")
    parser.add_argument("--features", type=int, default=4, help="Number of features (n)")
    parser.add_argument("--bits", type=int, default=16, help="Strict bit size of prime q")
    
    args = parser.parse_args()

    if(args.bits > 63):
        print("Max size of q can be 63 bits.")
        sys.exit(0)

    # Generate Parameters
    p, q, g, h = generate_subgroup_params(args.bits)
    
    # Generate linear model and private inputs
    # Use small ML weights and biases
    weights = [random.randint(1, min(100, q - 1)) for _ in range(args.features)]
    bias = random.randint(1, min(100, q - 1))
    # weights = [random.randint(1, q - 1) for _ in range(args.features)]
    # bias = random.randint(1, q - 1)

    x_binary = [random.choice([0, 1]) for _ in range(args.features)]
    r_blinding = [random.randint(1, q - 1) for _ in range(args.features)]
    
    # Write to files
    with open(args.public, "w") as f:
        f.write(f"p={p}\nq={q}\ng={g}\nh={h}\n")
        f.write(f"n={args.features}\n")
        f.write(f"weights={','.join(map(str, weights))}\n")
        f.write(f"bias={bias}\n")
        f.write(f"rounds={args.rounds}\n")
    print(f"[*] Generated {args.public}")

    with open(args.witness, "w") as f:
        f.write(f"x={','.join(map(str, x_binary))}\n")
        f.write(f"r={','.join(map(str, r_blinding))}\n")
    print(f"[*] Generated {args.witness}")

if __name__ == "__main__":
    main()