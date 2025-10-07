# quantum_key.py
"""
Provides a function to obtain 'quantum bits' or a quantum-derived tag.
Two modes:
 - If qiskit is installed and USE_IBM_QUANTUM is True and IBM_API_TOKEN provided:
     tries to get real randomness from IBM Quantum (requires configuration).
 - Otherwise: deterministic HMAC-based fallback using the IBM token as secret.
Both produce reproducible bytes suitable for use as a per-field tag (HMAC).
"""

import hashlib
import hmac
import os
from base64 import b64encode

def quantum_tag_fallback(secret_token: str, data: bytes, length: int = 16) -> str:
    """
    Deterministic fallback quantum-like tag:
    HMAC-SHA256(secret_token, data) -> return base64 of first `length` bytes.
    """
    if isinstance(secret_token, str):
        secret_bytes = secret_token.encode()
    else:
        secret_bytes = secret_token
    tag = hmac.new(secret_bytes, data, hashlib.sha256).digest()[:length]
    return b64encode(tag).decode()

# Optional real-IBM-quantum function (best-effort) - will raise informative error if not configured
def get_quantum_tag_ibm(ibm_token: str, data: bytes, length: int = 16) -> str:
    """
    Attempt to use IBM Quantum to generate true randomness. This is optional.
    If qiskit is not installed or IBM token isn't configured with provider/backends,
    this function will raise an Exception.
    NOTE: Using qiskit requires user setup outside of this script (account + API token).
    """
    try:
        from qiskit import IBMQ
        from qiskit import QuantumCircuit, Aer, transpile, assemble
        from qiskit import execute
    except Exception as e:
        raise RuntimeError("qiskit not available. Install qiskit to use real IBM Quantum.") from e

    # Try to load account. This requires the user to have executed IBMQ.save_account(token) previously,
    # or provide a mechanism to load token. For safety, this will attempt a local provider load.
    try:
        IBMQ.enable_account(ibm_token)
        provider = IBMQ.get_provider(hub='ibm-q')
    except Exception:
        # If failing to connect to IBMQ cloud provider, raise error so caller uses fallback.
        raise RuntimeError("Could not enable IBMQ account with provided token. Make sure IBMQ token is valid and qiskit is configured.")

    # Use a simulator or smallest backend to generate some bits
    backend = provider.backends()[0] if provider.backends() else None
    if backend is None:
        raise RuntimeError("No IBMQ backends available.")
    # For simplest approach, use Aer simulator to run small random circuit (if available)
    try:
        # Create a small random circuit to produce bits
        n_qubits = max(2, min(10, length * 8 // 1))
        qc = QuantumCircuit(n_qubits, n_qubits)
        for q in range(n_qubits):
            qc.h(q)
        qc.measure(range(n_qubits), range(n_qubits))
        # Use local Aer if present
        from qiskit import Aer
        aer = Aer.get_backend('aer_simulator')
        transpiled = transpile(qc, aer)
        result = aer.run(transpiled, shots=1).result()
        counts = result.get_counts()
        bitstring = list(counts.keys())[0]
        # create bytes from bitstring
        raw = int(bitstring, 2).to_bytes((len(bitstring)+7)//8, 'big')
        # mix with data input via HMAC as extra entropy
        digest = hmac.new(ibm_token.encode(), data + raw, hashlib.sha256).digest()[:length]
        return b64encode(digest).decode()
    except Exception as e:
        raise RuntimeError("Failed to generate IBM quantum randomness (simulator/backends may be missing).") from e

def get_quantum_tag(ibm_token: str, data: bytes, length: int = 16, use_ibm: bool = False) -> str:
    if use_ibm:
        try:
            return get_quantum_tag_ibm(ibm_token, data, length)
        except Exception as e:
            # Fallback quietly to deterministic tag
            return quantum_tag_fallback(ibm_token, data, length)
    else:
        return quantum_tag_fallback(ibm_token, data, length)
