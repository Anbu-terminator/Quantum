# backend/quantum_key.py
import requests, os, json
from config import IBM_API_TOKEN

IBM_QUANTUM_URL = "https://quantum-computing.ibm.com/api/RandomNumbers"  # Example URL

def get_quantum_challenge(nbytes: int = 16) -> str:
    """
    Fetch real quantum random bytes from IBM Quantum API.
    Returns hex string of length 2*nbytes.
    Fallback to pseudo-random if network/API fails.
    """
    headers = {
        "Authorization": f"Bearer {IBM_API_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "n": nbytes  # number of bytes requested
    }

    try:
        # NOTE: Replace this endpoint with IBM actual quantum randomness endpoint
        # IBM provides random numbers via https://quantum-computing.ibm.com/api/...
        r = requests.post(IBM_QUANTUM_URL, headers=headers, json=payload, timeout=5)
        r.raise_for_status()
        data = r.json()

        # Expected: data['result'] contains list of integers 0-255
        nums = data.get("result", [])
        if len(nums) < nbytes:
            raise ValueError("Insufficient quantum bytes returned")

        # Convert to hex
        hex_str = ''.join(f"{b:02x}" for b in nums[:nbytes])
        return hex_str

    except Exception as e:
        print(f"[Quantum] IBM API failed, using pseudo-random fallback: {e}")
        # fallback: pseudo-random bytes
        import random
        fallback = [random.randint(0, 255) for _ in range(nbytes)]
        hex_str = ''.join(f"{b:02x}" for b in fallback)
        return hex_str
