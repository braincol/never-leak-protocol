# NL Protocol Roadmap

> Community-facing roadmap for the Never-Leak Protocol project.
> Contributions welcome on any of these items.

## Current Status (v1.0.0-alpha)

- Specification v1.0: **complete** (9 chapters, 10,734 lines, 1,232 requirements)
- Reference implementation (Python): **complete** (907 tests passing, all 7 levels integrated)
- Website: **live** at neverleakprotocol.org

## Nice-to-Have Improvements

### 1. Strict Type Checking (`mypy --strict`)

Run `mypy --strict src/` over the reference implementation and fix any type errors. The codebase uses `from __future__ import annotations` throughout but hasn't been validated under mypy strict mode.

**Effort**: Small
**Impact**: Developer confidence, IDE support

### 2. Test Coverage Report (target: 90%+)

Run `pytest --cov=nl_protocol --cov-fail-under=90` and fill any coverage gaps. Add the coverage badge to the README.

**Effort**: Small
**Impact**: Quality assurance

### 3. Real Execution in the Pipeline (Level 3 Integration)

The `NLProvider.process_action()` currently resolves placeholders and validates through all 7 levels, but returns a synthetic success result rather than actually executing commands via `IsolatedExecutor`. Adding an optional `execute=True` mode would complete the full loop:

```python
response = await provider.process_action(request, execute=True)
# Actually runs the command in an isolated subprocess
```

**Effort**: Medium
**Impact**: Full end-to-end execution without manual wiring

### 4. Output Sanitization in Pipeline

`OutputSanitizer` is available as a property on the provider but is not automatically applied to execution output (since there's no real execution yet). Once item #3 is done, wire sanitization into the post-execution step.

**Effort**: Small (once #3 is done)
**Impact**: Security (last line of defense against secret leakage)

### 5. Package Publishing

Test `pip install -e .` and build a wheel (`python -m build`). Publish to PyPI as `nl-protocol`.

**Effort**: Small
**Impact**: Adoption

### 6. Additional Language SDKs

The Python reference implementation can guide ports to other languages:

- **TypeScript/Node.js** -- highest demand for MCP/agent ecosystem
- **Go** -- for infrastructure-level integrations
- **Rust** -- for performance-critical deployments

**Effort**: Large (per language)
**Impact**: Ecosystem growth

### 7. MCP Server Reference

Build an MCP (Model Context Protocol) server that wraps the NL Protocol provider, allowing any MCP-compatible AI agent to use NL Protocol for secret governance out of the box.

**Effort**: Medium
**Impact**: Direct integration with Claude, GPT, and other MCP-enabled agents

### 8. Conformance Certification Tool

Expand the conformance test suite into a standalone CLI tool that any implementation can run:

```bash
nl-conformance test --url http://localhost:8080 --tier advanced
```

**Effort**: Medium
**Impact**: Interoperability, trust

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All contributions should align with the specification in `specification/v1.0/`.
