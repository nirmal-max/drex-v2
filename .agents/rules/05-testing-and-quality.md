# Testing and Quality Assurance Rule

## Directives
1. **Automated Baseline**: Every module must have automated pytest test coverage verifying both positive and negative/fail-closed states.
2. **Deterministic Test Images**: Use synthetic loopback or RAM-backed `.img` fixtures (`create_test_image.py`) for reproducible recovery/sanitization assertions.
3. **No Inflated Metrics**: Never report synthetic or decision-engine passes as physical device passes.
4. **Regression Protection**: New components must not break existing Tkinter/WebUI lifecycles, background task manager, or certificate exports.
