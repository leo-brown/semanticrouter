/* Configuration relationships, not connectivity. Reverse endpoint equality is
   required before a BGP relationship can be labelled reciprocal. */
const host = value => (value || '').split('/')[0];
export function relationships(routers) {
  const owners = new Map();
  routers.forEach(router => router.addresses.forEach(address => owners.set(host(address.address),router.name)));
  const edges = new Map();
  routers.forEach(router => router.bgp.peers.forEach(peer => {
    const remote = owners.get(host(peer.remote_address));
    if(!remote || remote === router.name) return;
    const key = [router.name,remote].sort().join('|');
    if(!edges.has(key)) edges.set(key,{a:router.name,b:remote,sessions:[]});
    edges.get(key).sessions.push({from:router.name,to:remote,...peer});
  }));
  for(const edge of edges.values()) {
    const active = edge.sessions.filter(peer=>peer.enabled);
    const reciprocal = active.some(peer=>peer.local_address && active.some(other=>
      other.from === peer.to && other.to === peer.from &&
      host(other.remote_address) === host(peer.local_address) &&
      host(other.local_address) === host(peer.remote_address)));
    edge.status = reciprocal ? 'reciprocal' : active.length ? 'one-sided' : 'inactive';
  }
  routers.filter(router=>router.role==='bng').forEach(router=>router.interfaces.forEach(iface=>{
    const names=[iface.name.replace(/^bond-/,'').replace(/^sw-/,'switch-'),iface.name.replace(/^bond-/,'')];
    const match=routers.find(node=>['switch','sw'].includes(node.role)&&names.some(name=>name.toLowerCase()===node.name.toLowerCase()));
    if(match) {
      const key=[router.name,match.name].sort().join('|');
      if(!edges.has(key))edges.set(key,{a:router.name,b:match.name,inferred:true,status:'inactive'});
    }
  }));
  return [...edges.values()];
}
