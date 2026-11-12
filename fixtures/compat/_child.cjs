process.on('message', (m) => { process.send({ echo: m, argv: process.argv.slice(2), hasEnv: process.env.TT_PROBE || null }); if (m === 'bye') process.disconnect(); });
if (process.argv[2] === 'print') { console.log('child-out'); console.error('child-err'); process.exitCode = 3; process.disconnect && process.disconnect(); }
