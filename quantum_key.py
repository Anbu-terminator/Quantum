# backend/quantum_key.py
import os
import binascii
from config import IBM_API_TOKEN

def get_quantum_bytes(n_bytes=16):
    """
    Try to fetch n_bytes of quantum random data using Qiskit & IBM token.
    If Qiskit or IBM access fails, fall back to os.urandom.
    Returns bytes.
    """
    # Try Qiskit approach
    try:
        from qiskit import IBMQ, QuantumCircuit, transpile, assemble, Aer, execute
        # Attempt to load account
        if IBM_API_TOKEN and IBM_API_TOKEN.strip():
            try:
                IBMQ.enable_account(IBM_API_TOKEN)
                provider = IBMQ.get_provider(hub='ibm-q')  # may vary
                backend = provider.get_backend('ibmq_qasm_simulator')  # use a backend available to you
            except Exception:
                # fallback to local Aer simulator / or real backend if available
                backend = Aer.get_backend('qasm_simulator')
        else:
            from qiskit import Aer
            backend = Aer.get_backend('qasm_simulator')

        # create circuit to generate n_bytes * 8 bits
        n_bits = n_bytes * 8
        qc = QuantumCircuit(n_bits, n_bits)
        for i in range(n_bits):
            qc.h(i)
            qc.measure(i, i)

        transpiled = transpile(qc, backend=backend)
        qobj = assemble(transpiled, shots=1)
        job = backend.run(qobj)
        result = job.result()
        counts = result.get_counts()
        # counts is dict like {'01011..': 1}
        bitstring = next(iter(counts.keys()))
        # qiskit returns little/big-endian depending — normalize by taking first n_bits
        bitstring = bitstring.replace(" ", "")
        # ensure length
        if len(bitstring) < n_bits:
            # pad (shouldn't happen for most backends)
            bitstring = bitstring.zfill(n_bits)
        # convert to bytes
        b = int(bitstring, 2).to_bytes(n_bytes, 'big')
        return b
    except Exception as e:
        # fallback to OS randomness
        return os.urandom(n_bytes)
