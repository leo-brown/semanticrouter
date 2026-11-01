import { test } from 'node:test';
import assert from 'node:assert/strict';
import { relationships } from '../playground/topology.js';
const router = (name, address, peer) => ({
  name,
  role: 'border',
  addresses: [{ address }],
  interfaces: [],
  bgp: { peers: [peer] },
});
const x = () =>
  router('border-X', '192.0.2.1/32', {
    name: 'legacy-name',
    local_address: '192.0.2.1',
    remote_address: '192.0.2.2',
    enabled: true,
  });
const y = () =>
  router('bng-X1', '192.0.2.2/32', {
    name: 'irrelevant-name',
    local_address: '192.0.2.2',
    remote_address: '192.0.2.1',
    enabled: true,
  });
test('exact enabled reverse endpoints are reciprocal', () =>
  assert.equal(relationships([x(), y()])[0].status, 'reciprocal'));
test('enabled sessions with mismatched endpoints are not reciprocal', () => {
  const a = x(),
    b = y();
  b.bgp.peers[0].local_address = '192.0.2.3';
  assert.equal(relationships([a, b])[0].status, 'one-sided');
});
test('a disabled reverse session is not reciprocal', () => {
  const b = y();
  b.bgp.peers[0].enabled = false;
  assert.equal(relationships([x(), b])[0].status, 'one-sided');
});
test('both disabled sessions produce inactive relationship', () => {
  const a = x(),
    b = y();
  a.bgp.peers[0].enabled = false;
  b.bgp.peers[0].enabled = false;
  assert.equal(relationships([a, b])[0].status, 'inactive');
});
test('distribution inference is explicitly labelled', () => {
  const a = x();
  a.role = 'bng';
  a.interfaces = [{ name: 'bond-sw-X1' }];
  const sw = {
    name: 'switch-X1',
    role: 'switch',
    addresses: [],
    interfaces: [],
    bgp: { peers: [] },
  };
  const result = relationships([a, sw])[0];
  assert.equal(result.inferred, true);
  assert.equal(result.status, 'inactive');
});
