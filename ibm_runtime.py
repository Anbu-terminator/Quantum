# backend/ibm_runtime.py
import time
import traceback
from qiskit import QuantumCircuit
from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
from qiskit_ibm_runtime.exceptions import RuntimeJobFailure
from config import IBM_API_TOKEN, IBM_Q_BACKEND, IBM_Q_SHOTS

def _hadamard_circuit():
    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.measure(0, 0)
    return qc

def submit_quantum_job():
    """
    Submit a small sampler job and return a job handle info dict:
      { "job_id": "...", "backend": "..."}
    """
    if not IBM_API_TOKEN or "PASTE_YOUR_IBM_TOKEN" in IBM_API_TOKEN:
        raise RuntimeError("IBM_API_TOKEN not configured (set IBM_QUANTUM_TOKEN env var or edit config)")

    service = QiskitRuntimeService(token=IBM_API_TOKEN)
    backend = IBM_Q_BACKEND
    sampler = Sampler(service=service, backend=backend)
    qc = _hadamard_circuit()
    # synchronous submit returning a job object; we want job id and will poll
    job = sampler.run(circuits=[qc], shots=IBM_Q_SHOTS)
    # qiskit runtime Job object: get job_id via job.job_id or job._job.job_id depending on version
    job_id = None
    try:
        job_id = job.job_id
    except Exception:
        try:
            job_id = job._job.job_id
        except Exception:
            job_id = str(time.time()).replace('.', '')
    return {"job_id": job_id, "backend": backend, "internal_job": job}

def retrieve_job_result(job):
    """
    Given the runtime job object (the returned object from sampler.run)
    block until result and return simplified proof dict.
    """
    try:
        res = job.result()
    except RuntimeJobFailure as e:
        raise RuntimeError(f"Quantum job runtime failure: {e}")
    except Exception as e:
        raise RuntimeError(f"Error getting job result: {e}")

    # extract counts
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
        "job_id": getattr(res, "job_id", None) or None,
        "backend": getattr(res, "backend_name", None) or None,
        "timestamp": int(time.time()),
        "measured_bit": measured,
        "counts": counts
    }
    return proof
