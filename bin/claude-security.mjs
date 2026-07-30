#!/usr/bin/env node
import { main } from "../dist/cli.js";

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`error: ${err?.message ?? err}\n`);
    // Exit 1 is reserved for a completed policy violation; a thrown error is
    // invalid input or a runtime failure.
    process.exitCode = 2;
  });
