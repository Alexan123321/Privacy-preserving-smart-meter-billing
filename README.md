
# Smart Meter Security

## Introduction
This repository contains the proof-of-concept (PoC) implementations of the paper 'Smart Meter Data Security: Integrating ElGamal and Zero-Knowledge Proofs (ZKPs) for Privacy-Preserving Billing'.

## Project Description
This paper, ’Smart Meter Data Security: Integrating ElGamal and Zero-Knowledge Proofs (ZKPs) for Privacy-Preserving Billing’ addresses privacy concerns in smart meters through a distinct combination of three cryptographic schemes. We propose a system where smart meters use Elliptic Curve (EC) ElGamal encryption [8, 9] for secure data storage, transmission, processing (confidentiality), and generate Zero-Knowledge range Proofs [10], specifically Bulletproofs [11], for abnormal transaction filtering. Furthermore, we exploit the mathematical structural similarity between an EC ElGamal ciphertext and the EC Pedersen Commitment, upon which the Bulletproof is built, to ensure the integrity of the ciphertext by creating a Zero-Knowledge Proof of Equivalence
(ZKPe) proving that the Bulletproof indeed proves properties of the encrypted value. As such, the utility provider can reliably process bills via the control center using ElGamal’s homomorphic properties on
the Bitcoin curve, enabling billing on encrypted data without compromising consumer privacy, but it can also differentiate between normal and abnormal consumption data while preventing malicious intent. The research will conclude with an evaluation of this
system’s practical applicability. In summary, the key contribution of this study includes the proposal of a protocol that integrates:
- **Elliptic Curve (EC) ElGamal Encryption**: Used for secure data storage, transmission, and processing, ensuring confidentiality of energy consumption data.
- **Zero-Knowledge Proofs (ZKPs), Specifically Bulletproofs**: Employed for filtering abnormal consumption data while maintaining privacy.
- **Zero-Knowledge Proof of Equivalence (ZKPe)**: Ensures the integrity of the encrypted smart meter consumption data.

For further information, including references, please read the associated report. 

## License
This project is licensed under the terms of the MIT license.

## Acknowledgments
This project is based on research conducted in the field of smart meter data security. We acknowledge the contributions of all researchers and developers whose work has laid the foundation for this project.

---
