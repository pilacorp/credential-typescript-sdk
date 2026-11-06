import { BlockList, isIP } from 'node:net';

const v4 = new BlockList();
const v6 = new BlockList();

for (const p of [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.2.0/24',
  '192.88.99.2/32',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '240.0.0.0/4',
  '192.0.0.0/24',
  '224.0.0.0/4',
]) {
  const [addr, bits] = p.split('/');
  v4.addSubnet(addr, Number(bits), 'ipv4');
}

for (const p of [
  '64:ff9b:1::/48',
  '100::/64',
  '100:0:0:1::/64',
  '2001:db8::/32',
  '3fff::/20',
  '5f00::/16',
  'fc00::/7',
  'fe80::/10',
  '2001::/23',
  'ff00::/8',
  'fec0::/10',
]) {
  const [addr, bits] = p.split('/');
  v6.addSubnet(addr, Number(bits), 'ipv6');
}

export const ErrAddressBlocked = Object.assign(new Error('safehttp: blocked address'), { name: 'SafeHTTPError' });

export function blockedAddress(ip: string): boolean {
  const kind = isIP(ip);
  if (!kind) return true;
  const mapped = embeddedIPv4(ip, kind);
  if (mapped) return v4.check(mapped, 'ipv4');
  if (kind === 4) return v4.check(ip, 'ipv4');
  return v6.check(ip, 'ipv6');
}

function embeddedIPv4(ip: string, kind: number): string | null {
  if (kind !== 6) return null;
  const lower = ip.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const rest = ip.slice(7);
    if (isIP(rest) === 4) return rest;
  }
  return null;
}
