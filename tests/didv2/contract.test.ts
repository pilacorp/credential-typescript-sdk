import { Interface, Transaction, keccak256, id, type InterfaceAbi } from 'ethers';
import { DIDTypePeople } from '../../src/didv2';
import { DefaultProvider } from '../../src/didv2/signer';
import {
  Contract,
  DecodeWriterAnchors,
  SubtreeWriterRole,
  encodeWriterAnchorLog,
  writerAnchorTopic0,
} from '../../src/didv2/didcontract';
import { generateIssueDIDSignature } from '../../src/didv2/issuer';
import { DefaultDIDSMCAddress, DefaultChainID } from '../../src/didv2/config';
import artifact from '../../src/didv2/didcontract/did_registry_smc_abi.json';

describe('didv2 DID contract', () => {
  test('ABI topic0 and role', () => {
    expect(writerAnchorTopic0()).toBe('0x39edf358809bd8ab55bfce6add00fc1843a5c6e38ca5257fe7fb98b8bb145469');
    expect(SubtreeWriterRole).toBe(keccak256(Buffer.from('SUBTREE_WRITER_ROLE')));
    const iface = new Interface((artifact as { abi: InterfaceAbi }).abi);
    expect(iface.getFunction('hasRole')!.selector).toBe('0x91d14854');
    expect(id('BatchSubtreesAnchoredByWriter(address,address[],uint256[],bytes32[])')).toBe(writerAnchorTopic0());
  });

  test('createDID raw tx encodes capability args', async () => {
    const issuer = new DefaultProvider('11'.repeat(32));
    const did = new DefaultProvider('22'.repeat(32));
    const capId = `0x${'cd'.repeat(32)}`;
    const docHash = `0x${'11'.repeat(32)}`;
    const sig = await generateIssueDIDSignature(
      {
        contractAddress: DefaultDIDSMCAddress,
        issuerAddress: issuer.getAddress(),
        didAddress: did.getAddress(),
        didType: DIDTypePeople,
        epoch: 0n,
        capId,
      },
      issuer,
    );
    const contract = new Contract({
      rpcUrl: 'http://127.0.0.1:1',
      contractAddress: DefaultDIDSMCAddress,
      chainId: DefaultChainID,
    });
    const tx = await contract.createDIDTx(
      {
        issuerAddress: issuer.getAddress(),
        issuerSig: sig,
        docHash,
        capId,
        didType: DIDTypePeople,
        nonce: 0n,
      },
      did,
    );
    expect(tx.txHex).toMatch(/^[0-9a-f]+$/);
    expect(tx.txHash).toMatch(/^0x[0-9a-f]{64}$/);
    const parsed = Transaction.from(`0x${tx.txHex}`);
    expect(parsed.to!.toLowerCase()).toBe(DefaultDIDSMCAddress);
    const iface = new Interface((artifact as { abi: InterfaceAbi }).abi);
    const decoded = iface.decodeFunctionData('createDID', parsed.data);
    expect(decoded[0].toLowerCase()).toBe(issuer.getAddress());
    expect(Number(decoded[1])).toBe(DIDTypePeople);
  });

  test('DecodeWriterAnchors keeps registry batch order', () => {
    const registry = DefaultDIDSMCAddress;
    const writer = '0x5b6a5525e2c2d2428554b04d24b3bb5c1f3f5ae3';
    const n = 8;
    const dids = Array.from({ length: n }, (_, i) => `0x${(1000 + i).toString(16).padStart(40, '0')}`);
    const treeIndexes = Array.from({ length: n }, (_, i) => BigInt(i));
    const roots = Array.from({ length: n }, (_, i) => keccak256(`0x${i.toString(16).padStart(2, '0')}`));
    const other = '0x0000000000000000000000000000000000000bad';
    const receipt = {
      status: 1,
      logs: [
        encodeWriterAnchorLog(other, writer, dids.slice(0, 1), treeIndexes.slice(0, 1), roots.slice(0, 1), 3),
        encodeWriterAnchorLog(registry, writer, dids, treeIndexes, roots, 7),
      ],
    };
    const anchors = DecodeWriterAnchors(receipt, registry);
    expect(anchors).toHaveLength(n);
    expect(anchors[0].writer).toBe(writer.toLowerCase());
    expect(anchors[3].treeIndex).toBe(3n);
  });
});
