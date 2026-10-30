# Contributing

Use Node 24 or 26. Run `npm ci --ignore-scripts`, `npm run verify`, and the Python checks documented in the README when applicable. Use a feature branch and explain the behavior and validation in the pull request.

Include a failing security or correctness regression test for changed boundaries. Keep fixtures synthetic and label scanner outputs with provenance. Do not add account credentials, identifying organization data, remote rule downloads in offline demos, or claims unsupported by evidence. Use plain punctuation and avoid em dashes in source, documentation, and commit messages.

Keep dependencies locked. Actions must use full commit SHAs and minimal permissions. No workflow may execute a fork pull request with repository write credentials.
