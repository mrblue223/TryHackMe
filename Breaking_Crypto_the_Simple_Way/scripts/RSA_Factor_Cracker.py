import sys
try:
    from factordb.factordb import FactorDB
    from Crypto.Util.number import inverse, long_to_bytes
except ImportError:
    print("[-] Missing libraries. Run: pip install factordb-python pycryptodome --break-system-packages")
    sys.exit()

def crack_rsa(n, e, c):
    print(f"[*] Target Modulus (n): {str(n)[:20]}...{str(n)[-20:]}")
    print("[*] Contacting FactorDB...")

    # 1. Connect to FactorDB and get factors
    f = FactorDB(n)
    f.connect()
    factors = f.get_factor_list()

    if not factors or len(factors) < 2:
        print("[-] Error: FactorDB could not find factors for this n.")
        return

    print(f"[+] Found {len(factors)} factors!")
    
    # 2. Calculate Totient phi(n)
    # Works even if there are more than 2 factors (multi-prime RSA)
    phi = 1
    for p in factors:
        phi *= (p - 1)
    
    try:
        # 3. Derive Private Key (d)
        d = inverse(e, phi)
        
        # 4. Decrypt: m = c^d mod n
        m = pow(c, d, n)
        
        # 5. Convert to Flag
        flag = long_to_bytes(m).decode('utf-8', 'ignore')
        
        print("\n" + "="*30)
        print(f"CRACKED FLAG: {flag}")
        print("="*30)
    except Exception as err:
        print(f"[-] Decryption failed: {err}")

if __name__ == "__main__":
    # Challenge Values
    N_VAL = 43941819371451617899582143885098799360907134939870946637129466519309346255747
    E_VAL = 65537
    C_VAL = 9002431156311360251224219512084136121048022631163334079215596223698721862766
    
    crack_rsa(N_VAL, E_VAL, C_VAL)

