import os
import binascii
from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
from qiskit import QuantumCircuit

from config import IBM_API_TOKEN

def generate_quantum_nonce(n_bytes=16):
    """
    Generates a random nonce of n_bytes length using IBM Quantum.
    Falls back to os.urandom if the quantum service fails.
    Returns hex string of the random bytes.
    """
    try:
        # Connect to IBM Quantum Service
        service = QiskitRuntimeService(channel="ibm_quantum", token=IBM_API_TOKEN)
        sampler = Sampler(service=service)
        
        bits_needed = n_bytes * 8
        chunks = (bits_needed + 7) // 8  # each chunk = 8 qubits
        combined_bits = ''
        
        # Generate quantum random bits
        for _ in range(chunks):
            qc = QuantumCircuit(8, 8)
            qc.h(range(8))           # apply Hadamard gate to each qubit
            qc.measure(range(8), range(8))
            job = sampler.run(qc, shots=1)
            result = job.result()
            bitstr = list(result.counts().keys())[0]  # single shot
            combined_bits += bitstr
        
        # truncate to exact bits needed
        combined_bits = combined_bits[:bits_needed]
        
        # convert bits to bytes
        nonce_bytes = int(combined_bits, 2).to_bytes(n_bytes, byteorder='big')
        return binascii.hexlify(nonce_bytes).decode()
    
    except Exception as e:
        # Fallback to secure local randomness
        fallback = os.urandom(n_bytes)
        return binascii.hexlify(fallback).decode()

# ------------------ Test ------------------
if __name__ == "__main__":
    print("Quantum Nonce (16 bytes):", generate_quantum_nonce(16))
s
