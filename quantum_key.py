# quantum_key.py
from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
import config, binascii, os
def get_nonce(nbytes=16):
    try:
        svc = QiskitRuntimeService(channel="ibm_quantum", token=config.IBM_API_TOKEN)
        sampler = Sampler(service=svc)
        # generate bits
        from qiskit import QuantumCircuit
        bits_needed = nbytes*8
        chunks = (bits_needed+7)//8
        combined = ''
        for _ in range(chunks):
            qc = QuantumCircuit(8,8)
            qc.h(range(8))
            qc.measure(range(8), range(8))
            job = sampler.run(qc, shots=1)
            res = job.result()
            bitstr = list(res.counts().keys())[0]
            combined += bitstr
        combined = combined[:bits_needed]
        b = int(combined,2).to_bytes(nbytes, 'big')
        return binascii.hexlify(b).decode()
    except Exception as e:
        return binascii.hexlify(os.urandom(nbytes)).decode()
if __name__ == '__main__':
    print(get_nonce(16))
