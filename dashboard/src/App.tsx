import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowRight, Database, FileSearch, GitBranch, HeartPulse,
  LayoutDashboard, LockKeyhole, RefreshCw, Search, ShieldCheck, Workflow,
} from 'lucide-react';
import { Background, Controls, ReactFlow, type Edge, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { api, setToken } from './api';
import type { Event, Health, Metrics, Page, ProcessView, Rule, Tree } from './types';

type PageName = 'Overview'|'Events'|'Processes'|'Alerts'|'Rules'|'Health';
const pages: { name: PageName; icon: typeof Activity }[] = [
  { name: 'Overview', icon: LayoutDashboard }, { name: 'Events', icon: Activity },
  { name: 'Processes', icon: GitBranch }, { name: 'Alerts', icon: AlertTriangle },
  { name: 'Rules', icon: Workflow }, { name: 'Health', icon: HeartPulse },
];
const initiallyEmpty: Page<Event> = { items: [], total: 0, offset: 0, limit: 50, next_offset: null };
const fmtDate = (s?: string) => s ? new Date(s).toLocaleString(undefined,{hour12:false}) : '—';
const short = (s?: string, n=26) => s && s.length > n ? s.slice(0,n)+'…' : s || '—';
function Badge({ label }: { label: string }) { return <span className={`badge badge-${label.toLowerCase().replaceAll('_','-')}`}>{label.replaceAll('_',' ')}</span>; }
function Empty({ message }: { message: string }) { return <div className="empty"><FileSearch size={24}/><p>{message}</p></div>; }
function Detail({ item }: { item: Event | null }) {
  if (!item) return null;
  return <section className="detail" aria-label="Selected event evidence">
    <h3>Event evidence <span className="muted">{item.event_id}</span></h3>
    <div className="detailgrid"><div><span className="muted">Source</span><strong>{item.source}</strong></div><div><span className="muted">Timestamp provenance</span><strong>{item.timestamp_source}</strong></div></div>
    {item.detection && <div className="conditions"><strong>Matched conditions</strong><ul>{item.detection.matched_conditions.map(x=><li key={x}>{x}</li>)}</ul><strong>Trigger event IDs</strong><ul>{item.detection.triggering_event_ids.map(x=><li key={x}>{x}</li>)}</ul></div>}
    <pre>{JSON.stringify(item,null,2)}</pre>
  </section>;
}
function EventTable({ items, onSelect }: { items: Event[]; onSelect: (e:Event)=>void }) {
  if (!items.length) return <Empty message="No recorded events match these filters. No demo data is displayed."/>;
  return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Process</th><th>PID / UID</th><th>Host</th><th>Severity</th><th></th></tr></thead><tbody>{items.map(e =>
    <tr key={e.event_id}><td className="mono">{fmtDate(e.timestamp)}</td><td><Badge label={e.event_type}/></td><td><strong>{e.process.comm}</strong><small>{short(e.process.executable,40)}</small></td><td className="mono">{e.process.pid} / {e.process.uid}</td><td>{e.host.hostname}</td><td>{e.detection?<Badge label={e.detection.severity}/>:<span className="muted">—</span>}</td><td><button className="action" onClick={()=>onSelect(e)} aria-label={`Inspect ${e.event_id}`}><ArrowRight size={16}/></button></td></tr>
  )}</tbody></table></div>;
}
function useRefresh<T>(fetcher:(s:AbortSignal)=>Promise<T>, initial:T, interval=10000){
  const [data,setData] = useState<T>(initial), [error,setError]=useState(''),[loading,setLoading]=useState(true),[revision,refresh]=useState(0);
  useEffect(()=>{
    const controller=new AbortController();let running=false;
    async function load(){if(running)return;running=true;try{const result=await fetcher(controller.signal);if(!controller.signal.aborted){setData(result);setError('');}}catch(e){if(!controller.signal.aborted)setError(e instanceof Error?e.message:'Request failed');}finally{running=false;if(!controller.signal.aborted)setLoading(false);}}
    void load();const timer=window.setInterval(()=>void load(),interval);
    return()=>{controller.abort();window.clearInterval(timer)};
  },[fetcher,interval,revision]);
  return {data,error,loading,refresh:()=>refresh(n=>n+1)};
}
const eventFilter = (type: string,comm: string, uid: string, since: string,limit=50) => {
  const p = new URLSearchParams({order:'desc',limit:String(limit)});
  if(type)p.set('type',type);if(comm)p.set('comm',comm);if(uid)p.set('uid',uid);if(since)p.set('since',new Date(since).toISOString());
  return p;
};
function RecordedEvents({ alerts=false }: { alerts?: boolean }){
  const [type,setType]=useState(''),[comm,setComm]=useState(''),[uid,setUID]=useState(''),[since,setSince]=useState(''),[selected,setSelected]=useState<Event|null>(null);
  const [applied,setApplied]=useState({type:'',comm:'',uid:'',since:''});
  const fetcher=useCallback((signal:AbortSignal)=>{
    const p=eventFilter(alerts?'':applied.type,applied.comm,applied.uid,applied.since);
    return alerts ? api.alerts(p,signal) : api.events(p,signal);
  },[applied,alerts]);
  const {data,error,loading,refresh}=useRefresh(fetcher,initiallyEmpty,6000);
  return <><div className="section-top"><div><h2>{alerts?'Detection alerts':'Recorded events'}</h2><p className="muted">Newest first · read-only file view · automatically refreshes</p></div><button className="outline" onClick={refresh}><RefreshCw size={16}/> Refresh</button></div>
    <form className="filters" onSubmit={e=>{e.preventDefault();if(since && !Number.isFinite(Date.parse(since)))return;setApplied({type,comm:comm.trim(),uid:uid.trim(),since});}}>
      {!alerts && <select aria-label="Event type" value={type} onChange={e=>setType(e.target.value)}><option value="">All event types</option><option value="process_exec">Process exec</option><option value="process_exit">Process exit</option><option value="detection_alert">Alert</option></select>}
      <input aria-label="Command name" placeholder="Process name (e.g. bash)" value={comm} onChange={e=>setComm(e.target.value)}/>
      <input aria-label="User ID" placeholder="UID" inputMode="numeric" value={uid} onChange={e=>setUID(e.target.value)}/>
      <input aria-label="Since timestamp" type="datetime-local" value={since} onChange={e=>setSince(e.target.value)}/>
      <button type="submit"><Search size={16}/> Apply filters</button>
    </form>
    {error&&<div className="error" role="alert">API error: {error}. Check the recorded JSONL file and access token.</div>}
    <div className="pane"><div className="pane-heading"><span>{loading?'Loading…':`${data.total.toLocaleString()} matching records`}</span><span className="muted">Displaying up to 50 recent records</span></div><EventTable items={data.items} onSelect={setSelected}/></div>
    <Detail item={selected}/>
  </>;
}
function Overview({go}:{go:(p:PageName)=>void}){
  const h=useCallback((s:AbortSignal)=>api.health(s),[]);
  const m=useCallback((s:AbortSignal)=>api.metrics(s),[]);
  const {data:health,error:healthError}=useRefresh<Health|null>(h,null,10000);
  const {data:metrics,error:metricsError}=useRefresh<Metrics|null>(m,null,10000);
  return <><div className="section-top"><div><h2>Runtime security overview</h2><p className="muted">Operational view of <strong>recorded JSONL only</strong> · not live kernel status</p></div></div>
    {(healthError||metricsError)&&<div className="error">Could not read the API: {healthError||metricsError}</div>}
    <div className="stat-grid"><div className="stat"><span>Recorded events</span><strong>{metrics?.recorded_events?.toLocaleString()??'—'}</strong><small>Validated records in current file</small><Activity/></div>
      <div className="stat"><span>Detection alerts</span><strong>{metrics?.recorded_alerts?.toLocaleString()??'—'}</strong><small>Present in the recorded stream</small><AlertTriangle/></div>
      <div className="stat"><span>API file source</span><strong className="status-text">{health?.status==='ok'?'Available':'Unknown'}</strong><small>{health?.source_bytes?.toLocaleString()??'—'} bytes</small><Database/></div>
      <div className="stat"><span>Kernel loss / CPU</span><strong>N/A</strong><small>Not measurable from JSONL replay</small><HeartPulse/></div></div>
    <div className="cards-two"><section className="card"><h3>Investigation workflow</h3><p className="muted">Trace an observed process through its recorded activity and matched rule evidence. Missing parent links do not imply absence of activity.</p><div className="workflow"><span>Capture <small>eBPF agent</small></span><ArrowRight/><span>Analyze <small>YAML rules</small></span><ArrowRight/><span>Investigate <small>API + UI</small></span></div><button onClick={()=>go('Events')}>Explore events <ArrowRight size={15}/></button></section>
      <section className="card"><h3>Visibility limitations</h3><ul className="checklist"><li>Process exec / leader-exit hooks are not VM-verified.</li><li>Process ancestry is based on best-effort procfs enrichment.</li><li>Network and sensitive-file collection have not been implemented.</li><li>API operates on a bounded local JSONL file, not SQLite.</li></ul></section></div>
    <RecordedEvents/>
  </>;
}
function ProcessGraph({tree}:{tree:Tree}){
  const {nodes,edges}=useMemo(()=>{
    const depth=new Map<string,number>([[tree.root,0]]);let changed=true;
    for(let attempt=0;attempt<20&&changed;attempt++){changed=false;for(const e of tree.edges){const d=depth.get(e.from);if(d!==undefined && !depth.has(e.to)){depth.set(e.to,d+1);changed=true}}}
    const layers=new Map<number,number>();
    const nodes:Node[]=tree.nodes.map((p)=>{const d=depth.get(p.identity)??0;const at=layers.get(d)??0;layers.set(d,at+1);return{id:p.identity,position:{x:d*300,y:at*115},data:{label:`${p.process.comm} · PID ${p.process.pid}`},style:{background:'#161f30',border:'1px solid #35405a',color:'#e4e9f4',borderRadius:10,padding:'12px 14px',width:230,fontSize:13}}});
    const edges:Edge[]=tree.edges.map((e,i)=>({id:`edge-${i}`,source:e.from,target:e.to,animated:false,style:{stroke:'#5688d4'}}));return{nodes,edges};
  },[tree]);
  return <div className="flow"><ReactFlow nodes={nodes} edges={edges} fitView nodesDraggable={false} nodesConnectable={false} elementsSelectable={true}><Background color="#26354e" gap={22}/><Controls showInteractive={false}/></ReactFlow></div>;
}
function Processes(){
  const fetcher=useCallback((s:AbortSignal)=>api.processes(s),[]);
  const {data,error}=useRefresh<Page<ProcessView>>(fetcher,{items:[],total:0,offset:0,limit:200,next_offset:null},10000);
  const [selected,setSelected]=useState<string>(''),[tree,setTree]=useState<Tree|null>(null),[treeError,setTreeError]=useState('');
  useEffect(()=>{if(!selected)return;const c=new AbortController();setTree(null);api.tree(selected,c.signal).then(setTree).catch(e=>{if(!c.signal.aborted)setTreeError(String(e))});return()=>c.abort()},[selected]);
  return <><div className="section-top"><div><h2>Process explorer</h2><p className="muted">Only process identities captured in the recorded JSONL stream. Tree edges require observed parent identity.</p></div></div>
    {error&&<div className="error">{error}</div>}
    <div className="split"><div className="pane"><div className="pane-heading">Observed processes <span className="muted">{data.total}</span></div><div className="process-list">{data.items.map(p=><button key={p.identity} className={`process-row ${selected===p.identity?'selected':''}`} onClick={()=>{setSelected(p.identity);setTreeError('')}}><span><strong>{p.process.comm}</strong><small>PID {p.process.pid} · UID {p.process.uid}</small></span><ArrowRight size={16}/></button>)}{!data.items.length&&<Empty message="No enriched process identities recorded."/>}</div></div>
      <div className="pane"><div className="pane-heading">Observed descendant graph <Badge label="incomplete"/></div>{treeError&&<div className="error">{treeError}</div>}{tree?<><ProcessGraph tree={tree}/><p className="note">Only recorded relationships are shown; this graph is NOT a complete process tree.</p></>:<Empty message={selected?'Loading observed relationships…':'Select a process to inspect its observed descendants.'}/>}</div></div>
  </>;
}
function Rules(){const fn=useCallback((s:AbortSignal)=>api.rules(s),[]);const {data,error}=useRefresh(fn,{items:[] as Rule[],source:'not_configured'},30000);
  return <><div className="section-top"><div><h2>Detection rules</h2><p className="muted">Locally loaded YAML rule metadata; editing and hot reload are not implemented.</p></div></div>{error&&<div className="error">{error}</div>}
    <div className="rule-grid">{data.items.map(r=><div key={r.id} className="card"><div className="rule-heading"><code>{r.id}</code><Badge label={r.enabled?'enabled':'disabled'}/></div><h3>{r.name}</h3><div className="rule-footer"><Badge label={r.severity}/><span className="muted">{r.mitre_techniques?.join(', ')||'No ATT&CK tags'}</span></div></div>)}</div>{!data.items.length&&<Empty message="No rules configured in the API server."/>}
  </>}
function SystemHealth(){const h=useCallback((s:AbortSignal)=>api.health(s),[]),m=useCallback((s:AbortSignal)=>api.metrics(s),[]);
  const a=useRefresh<Health|null>(h,null,10000),b=useRefresh<Metrics|null>(m,null,10000);
  return <><div className="section-top"><div><h2>System health</h2><p className="muted">Reporting only values observable from the current recorded file.</p></div></div><div className="cards-two"><section className="card"><h3>Read-only API</h3><p>Source status: <Badge label={a.data?.status||'unknown'}/></p><p>Mode: <code>{a.data?.mode||'—'}</code></p><p>Agent health: <strong>{a.data?.agent_status||'unknown'}</strong></p><p>File size: {a.data?.source_bytes?.toLocaleString()??'—'} bytes</p>{a.error&&<div className="error">{a.error}</div>}</section>
  <section className="card"><h3>Monitoring coverage</h3><p>Event count: {b.data?.recorded_events??'—'}</p><p>Alert count: {b.data?.recorded_alerts??'—'}</p><p>Kernel drops: not available</p><p>Agent CPU, RAM, BPF maps: not available</p>{b.error&&<div className="error">{b.error}</div>}</section></div></>;
}
export default function App(){
  const [page,setPage]=useState<PageName>('Overview');const [tokenDraft,setTokenDraft]=useState('');const [tokenOpen,setTokenOpen]=useState(false);
  return <div className="shell"><aside className="sidebar"><div className="brand"><div className="brand-icon"><ShieldCheck size={25}/></div><div><strong>GHOSTTRACE</strong><small>RUNTIME SECURITY</small></div></div>
      <div className="sidebar-label">OPERATIONS</div><nav aria-label="Main navigation">{pages.map(p=><button key={p.name} className={`nav-item ${page===p.name?'active':''}`} onClick={()=>setPage(p.name)}><p.icon size={18}/><span>{p.name}</span></button>)}</nav>
      <div className="sidebar-bottom"><div className="side-status"><span className="dot"/> Read-only investigator</div><p>Source: locally recorded telemetry. No synthetic data.</p><small>GhostTrace · development build</small></div>
    </aside><div className="main"><header className="topbar"><div className="breadcrumbs"><span>SECURITY OPERATIONS</span><span className="slash">/</span><strong>{page}</strong></div><div className="top-actions"><span className="live-pill"><span className="dot"/> JSONL source</span><button className="outline" onClick={()=>setTokenOpen(x=>!x)}><LockKeyhole size={15}/> API access</button></div></header>
      {tokenOpen&&<form className="tokenbar" onSubmit={e=>{e.preventDefault();setToken(tokenDraft);setTokenOpen(false);setTokenDraft('');}}><label htmlFor="token">Bearer token (kept in memory only)</label><input id="token" autoComplete="off" type="password" value={tokenDraft} onChange={e=>setTokenDraft(e.target.value)} placeholder="Optional loopback API token"/><button type="submit">Use token</button></form>}
      <main className="content">{page==='Overview'?<Overview go={setPage}/>:page==='Events'?<RecordedEvents/>:page==='Alerts'?<RecordedEvents alerts/>:page==='Processes'?<Processes/>:page==='Rules'?<Rules/>:<SystemHealth/>}</main>
      <footer>GhostTrace · Observe Processes. Correlate Behavior. Detect Threats. <span>Monitoring-only · not comprehensive endpoint visibility</span></footer>
    </div></div>;
}
