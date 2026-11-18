export interface ChainProof {
  chain: string;
  tx_hash: string;
  root: string;
  path: string[];
  status: string;
}

export interface ProofResponse {
  did: string;
  root_did: string;
  tree_index: string;
  chains: ChainProof[];
}
