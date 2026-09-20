(() => {
  'use strict';
  const {details, identities} = __INSPECTOR_DATA__;
  const token = new URLSearchParams(location.hash.slice(1)).get('view') || '';
  const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const canvas = document.getElementById('mynetwork');
  const layout = document.createElement('div'); layout.id = 'inspection-layout';
  canvas.parentNode.insertBefore(layout, canvas); layout.appendChild(canvas);
  const panel = document.createElement('aside'); panel.id = 'process-inspector';
  panel.setAttribute('aria-label', 'Detalle del proceso seleccionado');
  panel.innerHTML = '<div class="inspector-toolbar"><strong>Detalle del proceso</strong><button id="clear-process" type="button">Limpiar</button></div><div id="process-detail" aria-live="polite"></div>';
  layout.appendChild(panel);
  const detail = document.getElementById('process-detail');
  const baseNodes = new Map(nodes.get().map(node => [String(node.id), node]));
  const baseEdges = edges.get();
  let selected = null;

  function notify(type, extra = {}) {
    if (window.parent !== window && token) {
      window.parent.postMessage({type, token, ...extra}, location.protocol === 'file:' ? '*' : location.origin);
    }
  }

  function paintSelection(id) {
    const neighbors = new Set(id === null ? [] : [id]);
    const incident = new Set();
    for (const edge of baseEdges) {
      if (String(edge.from) === id || String(edge.to) === id) {
        neighbors.add(String(edge.from)); neighbors.add(String(edge.to)); incident.add(edge.id);
      }
    }
    nodes.update([...baseNodes].map(([uid, node]) => ({
      id: node.id, chosen: false,
      color: {...node.color, highlight: {...node.color}, hover: {...node.color}},
      opacity: id === null || neighbors.has(uid) ? 1 : 0.55,
      font: {...node.font, size: uid === id ? 17 : (node.font?.size || 14)},
      shadow: {enabled: neighbors.has(uid), color: uid === id ? 'rgba(37,99,235,0.85)' : 'rgba(37,99,235,0.40)',
               size: uid === id ? 18 : 9, x:0, y:0}
    })));
    edges.update(baseEdges.map(edge => {
      const color = baseNodes.get(String(edge.from))?.color.border || '#456B8C';
      return {id:edge.id, chosen:false, width:incident.has(edge.id) ? 3.5 : edge.width,
        color:{color,highlight:color,hover:color,inherit:false,opacity:id === null || incident.has(edge.id) ? 1 : 0.35}};
    }));
  }

  function selectProcess(id, center = false) {
    id = String(id);
    if (!own(details, id) || !baseNodes.has(id)) return false;
    selected = id;
    paintSelection(id);
    network.selectNodes([id], false);
    detail.innerHTML = details[id]; detail.scrollTop = 0;
    detail.dataset.processUid = id;
    if (center) network.focus(id, {scale:Math.max(network.getScale(),0.8),animation:false});
    notify('tfm:process-selected', {uid:id,pid:identities[id].pid});
    return true;
  }

  function clear() {
    selected = null; network.unselectAll(); paintSelection(null);
    detail.textContent = 'Haz clic en un nodo o en el Top 10 para consultar sus evidencias.';
    delete detail.dataset.processUid;
    notify('tfm:process-selected', {uid:null});
  }
  document.getElementById('clear-process').addEventListener('click', clear);
  document.querySelector('.legend-help').addEventListener('click', event => {
    const help = document.getElementById('legend-help-text');
    help.hidden = !help.hidden; event.currentTarget.setAttribute('aria-expanded', String(!help.hidden));
  });
  network.on('click', event => {
    if (event.nodes.length) selectProcess(event.nodes[event.nodes.length - 1]);
    else if (selected !== null) network.selectNodes([selected], false);
  });
  window.addEventListener('message', event => {
    const message = event.data;
    if (window.parent === window || event.source !== window.parent || !message || message.token !== token || !token) return;
    if (location.protocol !== 'file:' && event.origin !== location.origin) return;
    if (message.type === 'tfm:ping') {notify('tfm:ready'); return;}
    if (message.type !== 'tfm:select-process') return;
    let id = null;
    if (typeof message.uid === 'string' && message.uid) {
      if (own(identities, message.uid) && (message.pid == null || identities[message.uid].pid === message.pid)) id = message.uid;
    } else if (Number.isSafeInteger(message.pid)) {
      const matches = Object.keys(identities).filter(uid => identities[uid].pid === message.pid);
      if (matches.length === 1) id = matches[0];
    }
    if (id === null || !selectProcess(id, true)) notify('tfm:selection-unavailable');
  });
  clear(); network.redraw(); network.fit({animation:false});
  notify('tfm:ready');
})();
