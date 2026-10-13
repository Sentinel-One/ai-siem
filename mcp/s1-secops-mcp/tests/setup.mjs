// Loaded with `node --import ./tests/setup.mjs --test ...`.
// Keeps the suite hermetic: no test may read the developer's real OS keychain.
// Child processes spawned with {...process.env} inherit it.
process.env.S1_KEYCHAIN = 'off';

// The server is read-only by default (1.5.5). Most suites exercise write handlers against mocked
// HTTP, so they run with write enabled. tests/readonly-1.5.5.test.mjs unsets or overrides this per
// test to prove the default and the refusals.
if (process.env.S1_READ_ONLY === undefined) process.env.S1_READ_ONLY = 'false';
