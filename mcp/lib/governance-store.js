"use strict";

const {
  sessionNucleusFromState,
} = require("./governance-contracts.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");

function readSessionNucleus(domain) {
  return sessionNucleusFromState(readSessionStateStrict(domain).state);
}

module.exports = {
  readSessionNucleus,
};
