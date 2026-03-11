# AI, Web3 & Emerging Attack Vectors Reference

## AI/ML Vulnerability Hunting

### OWASP Top 10 for LLMs (2025)

| Rank | Vulnerability |
|------|--------------|
| LLM01 | Prompt Injection (direct/indirect) |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain (compromised models/plugins) |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency (over-permissioned tools) |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses (RAG poisoning) |
| LLM09 | Misinformation generation |
| LLM10 | Unbounded Consumption (resource exhaustion) |

### Testing Approaches

**Prompt injection**: direct instruction override, indirect via content LLM processes, system prompt extraction, jailbreak patterns, tool/function abuse.

**AI-specific targets on huntr.com**: unauthenticated model endpoints, training data exposure, adversarial inputs, prompt injection in AI features, plugin abuse, embedding injection.

Prompt injection surged 540% in 2025. 1,121 HackerOne programs included AI in scope.

---

## Smart Contract Security

### Common Vulnerabilities

1. **Reentrancy**: external call before state update. Fix: Checks-Effects-Interactions + ReentrancyGuard.
2. **Integer overflow/underflow**: pre-Solidity 0.8. Fix: use >= 0.8 or SafeMath.
3. **Access control**: missing modifiers on critical functions.
4. **Front-running (MEV)**: mempool transaction visibility.
5. **Oracle manipulation**: flash loan to manipulate spot price.

### Testing Tools

Slither (static analysis), Mythril (symbolic execution), Echidna (fuzzing), Foundry (testing framework), Certora Prover (formal verification).

### Immunefi Methodology

1. Understand protocol documentation
2. Read contracts line by line
3. Map state machine and invariants
4. Look for invariant violations
5. Test with Foundry fork tests
6. Focus: fund extraction, access control bypass, logic errors, flash loan vectors, governance manipulation

---

## DeFi Protocol Attacks

### Flash Loan Attacks

Pattern: borrow (no collateral) -> manipulate oracle -> interact at manipulated price -> profit -> repay. All in single transaction.

### Bridge Vulnerabilities

Focus: signature verification bypass, replay attacks, validator compromise, message queue manipulation, deposit/withdrawal accounting errors.

Notable: Wormhole ($320M), Ronin ($625M), Nomad ($190M).

### Governance Attacks

Flash loan governance, proposal spam, timelock bypass, proxy upgrade manipulation.

---

## Supply Chain Attacks

### Dependency Confusion

Register internal package names on public registries with higher version. Build systems may pull public version.

Detection: find internal names (JS source maps, errors, GitHub), check public registries.

### CI/CD Pipeline Exploitation

GitHub Actions: workflow injection via issue titles/PR bodies, GITHUB_TOKEN over-permission, self-hosted runner escape, secret extraction.

### Package Hijacking

Typosquatting, maintainer account takeover, abandoned package takeover, star-jacking.

Tools: Socket.dev, Snyk, npm/pip/cargo audit.

---

## Emerging Attack Surfaces

### Edge Computing

CDN/Edge worker vulns: cache key manipulation, edge function injection, origin server exposure, TLS termination issues, env variable leakage.

### Browser Extensions

Content script injection (XSS), background script message handling, over-permissive manifest, storage data leakage, update hijacking.

Testing: unpack extension, review manifest.json, analyze content scripts, check message passing, test storage.

### WebAssembly (WASM)

Memory corruption, side-channel attacks, binary analysis for hardcoded secrets, JS-WASM interface issues.

Tools: wasm-decompile, wabt, Wasabi.
