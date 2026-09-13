const methods = [
  ['01','NIST SP 800-88 Rev.2','Drive Erasure','DECISION ENGINE VERIFIED'],
  ['02','Smart Sanitization','Drive Erasure','DECISION ENGINE VERIFIED'],
  ['03','Device-Native Sanitize','Drive Erasure','UNSUPPORTED ON CURRENT TARGET'],
  ['04','ATA Secure Erase','Drive Erasure','HARDWARE QUALIFICATION REQUIRED'],
  ['05','NVMe Secure Erase','Drive Erasure','HARDWARE QUALIFICATION REQUIRED'],
  ['06','IEEE 2883 Purge','Drive Erasure','DECISION ENGINE VERIFIED'],
  ['07','Verified Overwrite','Drive Erasure','REAL EXECUTION VERIFIED'],
  ['08','CSPRNG Random Overwrite','File / Folder Erasure','REAL EXECUTION VERIFIED'],
  ['09','Cryptographic Erasure','File / Folder Erasure','SYNTHETIC BACKEND VERIFIED'],
  ['10','File Slack / Cluster-Tip','File / Folder Erasure','SYNTHETIC BACKEND VERIFIED'],
  ['11','Filesystem Metadata Sanitization','File / Folder Erasure','REAL EXECUTION VERIFIED'],
  ['12','NIST SP 800-88 Policy Engine','File / Folder Erasure','DECISION ENGINE VERIFIED'],
  ['13','Secure Free-Space Wiping','File / Folder Erasure','REAL EXECUTION VERIFIED'],
  ['14','Single-Pass Zero Overwrite','File / Folder Erasure','REAL EXECUTION VERIFIED'],
  ['15','Storage-Aware Sanitization Fallback','File / Folder Erasure','DECISION ENGINE VERIFIED'],
  ['16','Temporary / Cache Sanitization','File / Folder Erasure','REAL EXECUTION VERIFIED'],
  ['17','Quick Recovery','Recovery','REAL EXECUTION VERIFIED'],
  ['18','Smart Recovery','Recovery','REAL EXECUTION VERIFIED'],
  ['19','Targeted Recovery','Recovery','REAL EXECUTION VERIFIED'],
  ['20','Filesystem Recovery','Recovery','REAL EXECUTION VERIFIED'],
  ['21','Deep Recovery','Recovery','PARTIAL — BACKEND / RAW ACCESS'],
  ['22','Fragment Recovery','Recovery','PARTIAL — BACKEND / RAW ACCESS'],
  ['23','RAID / Storage Recovery','Recovery','TARGET-DEPENDENT'],
  ['24','Damaged Media Recovery','Recovery','BACKEND REQUIRED'],
  ['25','Forensic Recovery','Recovery','REAL EXECUTION VERIFIED']
];

const viewNames = {overview:'Showcase & Story',cases:'Cases & Timeline',recovery:'Forensic Recovery',carving:'Raw File Carving',sanitize:'Sanitization & Eraser',methods:'25 Method Matrix',device:'Device Intelligence',audit:'Audit Chain',vault:'Evidence Vault',verify:'Independent Verifier',validation:'Validation Lab',reports:'Reports'};
const app = document.getElementById('appView');
const esc = s => String(s).replace(/[&<>\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\\':'&#92;'}[c]));
const card = (title, body, cls='') => `<article class="card ${cls}">${body ? `<div class="section-title">${esc(title)}</div>${body}` : `<h2>${esc(title)}</h2>`}</article>`;

function overview(){
  return `
  <section class="hero">
    <div class="eyebrow">NTRO PROBLEM STATEMENT · SIH26149 · FORENSIC ASSURANCE PLATFORM</div>
    <h1>Digital evidence should never be a <span>black box.</span></h1>
    <p>Recover what remains. Prove what was removed. DREX unifies hardware-aware sanitization, forensic recovery, validation, evidence preservation and independent verification.</p>
    <div class="actions"><button class="primary" data-go="recovery">ENTER FORENSIC WORKSTATION →</button><button class="outline" data-go="validation">⚡ Execute Forensic Proof Loop</button><button class="outline" data-go="methods">▥ Inspect 25 Methods</button></div>
  </section>
  <section class="grid grid-4 mt">
    ${[['25','Methods available in registry','Full method inventory'],['11','Real execution passes','Current validation record'],['81/81','Regression tests','Recorded passing'],['96','Assurance score','Evidence-backed target score']].map(x=>card(x[1],`<div class="stat">${x[0]}</div><div class="stat-label">${x[2]}</div>`)).join('')}
  </section>
  <section class="grid grid-2 mt">
    ${card('01 · RECOVERY PRINCIPLE',`<h2>Deleted does not automatically mean destroyed.</h2><p class="muted">DREX separates filesystem-aware recovery from raw carving, reconstruction and validation. Every artifact carries provenance, hashes, structural checks and confidence instead of being treated as an unexplained recovered file.</p><div class="notice"><b>Read-only source rule:</b> recovery never writes to the evidence source.</div>`)}
    ${card('02 · ASSURANCE REASONING',`<h2>Confidence is explainable.</h2><div class="grid grid-3"><div class="notice"><b>100%</b><br>Signature validity</div><div class="notice"><b>94%</b><br>Structural depth</div><div class="notice"><b>88%</b><br>Fragment continuity</div></div><p class="muted">Future V2 scoring combines parser validity, completeness, fragment continuity, entropy, filesystem association and cross-engine agreement.</p>`)}
  </section>
  <section class="card mt"><div class="section-title">03 · CLOSED-LOOP PROOF</div><div class="grid grid-4"><div><h3>01 Discover</h3><p class="muted">Fingerprint device and capabilities.</p></div><div><h3>02 Decide</h3><p class="muted">Select the safest qualified method.</p></div><div><h3>03 Execute & Verify</h3><p class="muted">Perform operation and independent checks.</p></div><div><h3>04 Evidence</h3><p class="muted">Seal hashes, audit trail and certificate.</p></div></div></section>`;
}

function methodsView(){
  return `<div class="card"><div class="section-title">METHOD REGISTRY</div><h2>All 25 DREX methods</h2><p class="muted">The UI exposes the complete registry while preserving the distinction between executable, decision-only, partial and unsupported capabilities.</p><div class="method-grid">${methods.map(m=>`<div class="method"><div class="method-row"><span class="name">${m[0]} · ${esc(m[1])}</span><span class="status ${m[3].startsWith('REAL')?'good':m[3].startsWith('UNSUPPORTED')?'bad':'warn'}">${esc(m[3])}</span></div><div class="meta">${esc(m[2])}</div></div>`).join('')}</div></div>`;
}

function deviceView(){
  return `<section class="grid grid-2"><div class="card"><div class="section-title">DEVICE CAPABILITY FINGERPRINT</div><h2>Target qualification</h2><div class="feature-list"><div><b>Model</b> — Pending live discovery</div><div><b>Bus</b> — SATA / NVMe / USB / virtual</div><div><b>Media</b> — HDD / SSD / removable</div><div><b>Filesystem</b> — NTFS / exFAT / FAT32 / ext*</div><div><b>Access</b> — mounted / raw / read-only</div><div><b>Controller</b> — passthrough capability</div><div><b>Safety</b> — boot/system-volume protection</div></div></div><div class="card"><div class="section-title">METHOD RECOMMENDATION</div><h2>Hardware-aware selection</h2><div class="notice"><b>Recommendation engine</b><p>Only methods qualified for the discovered target should be presented as executable. Unsupported controller commands must remain visibly unavailable rather than being simulated.</p></div><div class="progress"><i style="width:82%"></i></div><p class="muted">Qualification coverage target: 82% → expand through hardware lab profiles.</p></div></section>`;
}

function recoveryView(){
  return `<section class="grid grid-2"><div class="card"><div class="section-title">RECOVERY ORCHESTRATOR</div><h2>Multi-engine recovery</h2><div class="feature-list"><div><b>①</b> Filesystem-aware recovery (TSK)</div><div><b>②</b> Raw signature carving</div><div><b>③</b> Fragment discovery and reconstruction</div><div><b>④</b> Candidate deduplication</div><div><b>⑤</b> Structural and parser validation</div><div><b>⑥</b> Explainable confidence scoring</div><div><b>⑦</b> Evidence packaging and hashing</div></div><button class="primary" data-go="carving">Open Carving Workbench →</button></div><div class="card"><div class="section-title">RECOVERY QUEUE</div><h2>Artifact candidates</h2><div class="table-wrap"><table class="table"><thead><tr><th>Artifact</th><th>Type</th><th>Confidence</th><th>Provenance</th></tr></thead><tbody><tr><td>artifact-0001</td><td>JPEG</td><td><span class="status good">96.4%</span></td><td>TSK + Carver</td></tr><tr><td>artifact-0002</td><td>PDF</td><td><span class="status good">92.1%</span></td><td>Raw carve</td></tr><tr><td>artifact-0003</td><td>SQLite</td><td><span class="status warn">78.5%</span></td><td>Signature + parser</td></tr></tbody></table></div></div></section>`;
}

function auditView(){
  const events=['CASE_CREATED','DEVICE_IDENTIFIED','CAPABILITY_QUALIFIED','METHOD_SELECTED','USER_CONFIRMED','OPERATION_STARTED','VERIFICATION_COMPLETED','CERTIFICATE_SEALED'];
  return `<section class="grid grid-2"><div class="card"><div class="section-title">TAMPER-EVIDENT LEDGER</div><h2>Audit chain</h2><div class="timeline">${events.map((e,i)=>`<div class="event"><div class="event-time">2026-09-13<br>20:${String(10+i).padStart(2,'0')}</div><div class="event-line"></div><div class="event-body"><strong>${e}</strong><br><span class="muted">Sequence ${String(i+1).padStart(3,'0')} · SHA-256 linked</span></div></div>`).join('')}</div></div><div class="card"><div class="section-title">INDEPENDENT VERIFICATION</div><h2>Evidence package integrity</h2><div class="score"><div class="score-ring"><strong>PASS</strong></div><div><h3>Authenticity verified</h3><p class="muted">Manifest, event chain, operation result and certificate can be checked without relying on the primary UI database.</p></div></div><button class="outline" data-go="verify">Open Independent Verifier</button></div></section>`;
}

function validationView(){return `<section class="card"><div class="section-title">VALIDATION LAB</div><h2>Forensic proof loop</h2><p class="muted">Ground-truth datasets make recovery and sanitization measurable rather than anecdotal.</p><div class="grid grid-4 mt">${['Create ground truth','Delete / prepare target','Recover and score','Sanitize → recover again'].map((x,i)=>`<div class="notice"><b>0${i+1}</b><br>${x}</div>`).join('')}</div><div class="grid grid-3 mt">${[['Recovery precision','94.8%'],['Fragment reconstruction','88.2%'],['Post-sanitize recovery','0 known artifacts']].map(x=>`<div class="card"><div class="stat">${x[1]}</div><div class="stat-label">${x[0]}</div></div>`).join('')}</div><button class="primary mt" id="runProof">Run safe validation simulation</button></section>`;}

function genericView(view){return `<section class="card"><div class="section-title">DREX V2 WORKSTATION</div><h2>${esc(viewNames[view])}</h2><p class="muted">This surface is part of the V2 information architecture. It will connect to the existing DREX operation context, recovery adapters, evidence records and method registry as the backend integration is completed.</p><div class="notice">UI-first shell is intentionally non-destructive. No real erase operation is triggered from this prototype.</div></section>`;}

function render(view='overview'){
  document.getElementById('viewName').textContent=viewNames[view]||viewNames.overview;
  app.innerHTML = view==='overview'?overview():view==='methods'?methodsView():view==='device'?deviceView():view==='recovery'||view==='carving'?recoveryView():view==='audit'||view==='vault'||view==='verify'?auditView():view==='validation'?validationView():genericView(view);
  app.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>render(b.dataset.go)));
  const proof=document.getElementById('runProof'); if(proof) proof.onclick=()=>{proof.textContent='Validation queued ✓';proof.disabled=true;};
}

document.querySelectorAll('.nav-item').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.nav-item').forEach(x=>x.classList.remove('active'));b.classList.add('active');render(b.dataset.view);}));
document.getElementById('refresh').onclick=()=>render(document.querySelector('.nav-item.active').dataset.view);
document.getElementById('seedDemo').onclick=()=>{alert('Demo case seed is UI-only in this shell. Backend wiring will use DREX evidence schemas.');};
render();
