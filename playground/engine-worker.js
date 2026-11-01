/* All config parsing, assertions and rendering use the shipped Python sources.
   Payloads are data, never Python code. A worker keeps the interface responsive. */
let ready;
async function boot() {
  const {loadPyodide} = await import('./runtime/pyodide.mjs');
  const py = await loadPyodide({indexURL:new URL('./runtime/',self.location.href).href});
  const response = await fetch('./engine.json');
  if (!response.ok) throw new Error('Unable to load middleware sources');
  const sources = await response.json();
  for (const [name, text] of Object.entries(sources)) {
    const path = '/app/' + name;
    py.FS.mkdirTree(path.slice(0,path.lastIndexOf('/')));
    py.FS.writeFile(path,text);
  }
  py.runPython('import sys\nsys.path.insert(0,"/app")\nfrom playground_bridge import handle');
  postMessage({type:'ready'});
  return py;
}
self.onmessage = async ({data}) => {
  try {
    if (!ready) ready = boot();
    const py = await ready;
    if (data.action === 'boot') return;
    py.globals.set('request_json',JSON.stringify(data));
    const result = JSON.parse(py.runPython('handle(request_json)'));
    postMessage({id:data.id,...result});
  } catch (error) {
    postMessage({id:data.id,type:'error',ok:false,error:String(error.message || error)});
  }
};
