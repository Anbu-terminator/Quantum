# backend/ibm_runtime.py
import time
from qiskit import QuantumCircuit
from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
from config import IBM_API_TOKEN, IBM_Q_BACKEND, IBM_Q_SHOTS

def _hadamard_circuit():
    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.measure(0, 0)
    return qc

def submit_quantum_job():
    service = QiskitRuntimeService(token=IBM_API_TOKEN)
    backend = IBM_Q_BACKEND
    sampler = Sampler(service=service, backend=backend)
    qc = _hadamard_circuit()
    job = sampler.run(circuits=[qc], shots=IBM_Q_SHOTS)
    try:
        job_id = job.job_id
    except Exception:
        job_id = str(time.time()).replace('.', '')
    return {"job_id": job_id, "internal_job": job}

def retrieve_job_result(job):
    res = job.result()
    counts = {}
    try:
        quasi = res.quasi_dists[0]
        probs = quasi.binary_probabilities()
        for k, p in probs.items():
            counts[k] = int(p * IBM_Q_SHOTS)
    except Exception:
        try:
            counts = res.get_counts(0)
        except Exception:
            counts = {}
    measured = "0"
    if counts:
        measured = max(counts.items(), key=lambda kv: (kv[1], kv[0]))[0]
    proof = {
        "job_id": getattr(res, "job_id", None),
        "backend": getattr(res, "backend_name", None),
        "timestamp": int(time.time()),
        "measured_bit": measured,
        "counts": counts
    }
    return proof
