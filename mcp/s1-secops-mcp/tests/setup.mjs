// Loaded with `node --import ./tests/setup.mjs --test ...`.
// Keeps the suite hermetic: no test may read the developer's real OS keychain.
// Child processes spawned with {...process.env} inherit it.
process.env.S1_KEYCHAIN = 'off';
