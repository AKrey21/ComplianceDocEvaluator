// config.js
export default {
  weights: { privacy_app: 0.35, security_e8: 0.25, cdss_exemption: 0.20, contract_fairness: 0.10, vendor_sharing: 0.10 },
  hardFailCaps: { privacyWhenCoreMissing: true },
  maxTokensPerChunk: 6000,
  overlapChars: 800
};
