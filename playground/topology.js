/* Configuration relationships, not connectivity. Reverse endpoint equality is
   required before a BGP relationship can be labelled reciprocal. */
const host = (value) => (value || '').split('/')[0];
/** Return configured relationships, requiring exact reverse BGP endpoints for reciprocity.
 * Peer names are labels only. An inferred bond-to-switch link is always marked separately. */
export function relationships(routers) {
  const owners = new Map();
  routers.forEach((router) =>
    router.addresses.forEach((address) =>
      owners.set(host(address.address), router.name),
    ),
  );
  const edges = new Map();
  routers.forEach((router) =>
    router.bgp.peers.forEach((peer) => {
      const remote = owners.get(host(peer.remote_address));
      if (!remote || remote === router.name) return;
      const key = [router.name, remote].sort().join('|');
      if (!edges.has(key)) edges.set(key, { a: router.name, b: remote, sessions: [] });
      edges.get(key).sessions.push({ from: router.name, to: remote, ...peer });
    }),
  );
  for (const edge of edges.values()) {
    const active = edge.sessions.filter((peer) => peer.enabled);
    const reciprocal = active.some(
      (peer) =>
        peer.local_address &&
        active.some(
          (other) =>
            other.from === peer.to &&
            other.to === peer.from &&
            host(other.remote_address) === host(peer.local_address) &&
            host(other.local_address) === host(peer.remote_address),
        ),
    );
    edge.status = reciprocal ? 'reciprocal' : active.length ? 'one-sided' : 'inactive';
  }
  routers
    .filter((router) => router.role === 'bng')
    .forEach((router) =>
      router.interfaces.forEach((iface) => {
        const names = [
          iface.name.replace(/^bond-/, '').replace(/^sw-/, 'switch-'),
          iface.name.replace(/^bond-/, ''),
        ];
        const match = routers.find(
          (node) =>
            ['switch', 'sw'].includes(node.role) &&
            names.some((name) => name.toLowerCase() === node.name.toLowerCase()),
        );
        if (match) {
          const key = [router.name, match.name].sort().join('|');
          if (!edges.has(key))
            edges.set(key, {
              a: router.name,
              b: match.name,
              inferred: true,
              status: 'inactive',
            });
        }
      }),
    );
  // Handoff uplinks are configuration hints, not BGP sessions or link-state
  // observations. Match whole device names/aliases on physical/bond interfaces;
  // VLAN names may repeat uplink labels and must not create additional links.
  for (const router of routers)
    for (const iface of router.interfaces) {
      if (!['ethernet', 'bonding'].includes(iface.kind)) continue;
      for (const remote of routers) {
        if (remote.name === router.name || ![router.role, remote.role].includes('nni'))
          continue;
        const aliases = [remote.name, remote.name.replace(/^switch-/i, 'sw-')];
        const label = iface.name.toLowerCase();
        if (
          !aliases.some((name) => {
            const target = name.toLowerCase();
            return label === target || label.endsWith('-' + target);
          })
        )
          continue;
        const key = [router.name, remote.name].sort().join('|');
        if (!edges.has(key))
          edges.set(key, {
            a: router.name,
            b: remote.name,
            inferred: true,
            status: 'inactive',
            kind: 'configured-uplink',
          });
      }
    }
  return [...edges.values()];
}
