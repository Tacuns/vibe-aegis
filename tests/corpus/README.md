# Rule corpus

`<RULE>/vulnerable/` is a realistic implementation with the flaw the rule targets;
`<RULE>/safe/` is the realistic **correct** implementation of the same feature.
`TestCorpus` in `tests/test_scanner.py` requires each rule to fire on the first and stay
silent on the second, and fails when a rule id has neither a pair here nor an entry in
`CORPUS_EXEMPT` naming the test that covers it.

- Build output is stored as `dist.fixture/` and renamed to `dist/` in a temporary copy:
  the repository's `.gitignore` excludes `dist/`.
- The only credential is the generic value `k3Jx9m...`, used in a few vulnerable cases. It
  is not a real key and has no provider format; generic secret scanners such as
  gitleaks' `generic-api-key` will (correctly) flag those files.
