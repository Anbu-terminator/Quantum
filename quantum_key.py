import random, string

def get_quantum_challenge():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
