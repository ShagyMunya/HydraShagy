import { useState, type FormEvent, type ReactNode } from 'react'
import type { Assessment, Evidence, Finding } from './types'

type SourceTool = 'burp_suite' | 'wireshark' | 'strix' | 'metasploit' | 'sqlmap' | 'john' | 'hashcat' | 'hydra' | 'pentera' | 'nodezero'
type Props = {
  assessments: Assessment[]
  findings: Finding[]
  evidence: Evidence[]
  currentAssessment: string
  upload: (form: FormData) => Promise<any>
  afterUpload: () => void
}

const field='w-full rounded-lg border border-[#dfe7e2] bg-white px-3 py-2.5 text-sm text-[#25332c] focus-ring'
const btn='inline-flex items-center justify-center gap-2 rounded-lg bg-[#247653] px-3.5 py-2.5 text-sm font-semibold text-white hover:bg-[#1b6445] disabled:opacity-50'

export default function ToolReportImporter({assessments,findings,evidence,currentAssessment,upload,afterUpload}:Props){
  const [source,setSource]=useState<SourceTool>('burp_suite')
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const imported=evidence.filter(item=>item.source_tool!=='manual')
  const accept=source==='burp_suite'||source==='metasploit'?'.xml':source==='wireshark'?'.csv,.pcap,.pcapng':source==='strix'?'.json,.sarif':undefined
  const labels:Record<SourceTool,string>={burp_suite:'Burp Suite',wireshark:'Wireshark',strix:'Strix',metasploit:'Metasploit',sqlmap:'sqlmap',john:'John the Ripper',hashcat:'Hashcat',hydra:'Hydra',pentera:'Pentera',nodezero:'NodeZero'}
  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault();const form=event.currentTarget;setError('');setBusy(true)
    try{await upload(new FormData(form));form.reset();setSource('burp_suite');afterUpload()}
    catch(e){setError(e instanceof Error?e.message:'Report import failed')}
    finally{setBusy(false)}
  }
  return <>
    <Card>
      <div className="border-b border-[#edf1ee] px-4 py-4"><h2 className="text-sm font-semibold">Import an external tool report</h2><p className="mt-1 text-[10px] leading-4 text-[#929d96]">Upload output from an assessor-run tool for encrypted storage and a bounded review summary. HydraShagy stores these externally generated reports; see Recon & scans for runnable local workflows.</p></div>
      <form className="grid gap-3 p-4 md:grid-cols-2" onSubmit={submit}>
        <label className="block"><span className="mb-1.5 block text-xs font-semibold text-[#56635c]">Assessment</span><select className={field} name="assessment_id" required defaultValue={currentAssessment}><option value="">Select assessment</option>{assessments.map(a=><option key={a.id} value={a.id}>{a.name}</option>)}</select></label>
        <label className="block"><span className="mb-1.5 block text-xs font-semibold text-[#56635c]">Source tool</span><select className={field} name="source_tool" value={source} onChange={e=>setSource(e.target.value as SourceTool)}><option value="burp_suite">Burp Suite · XML issue report</option><option value="wireshark">Wireshark · packet summary CSV or PCAP/PCAPNG</option><option value="strix">Strix · vulnerabilities.json or SARIF</option><option value="metasploit">Metasploit · XML database export</option><option value="sqlmap">sqlmap · encrypted artifact</option><option value="john">John the Ripper · redacted output summary</option><option value="hashcat">Hashcat · redacted output summary</option><option value="hydra">Hydra · redacted output summary</option><option value="pentera">Pentera · encrypted artifact</option><option value="nodezero">NodeZero · encrypted artifact</option></select></label>
        <label className="block"><span className="mb-1.5 block text-xs font-semibold text-[#56635c]">Link finding (optional)</span><select className={field} name="finding_id" defaultValue=""><option value="">No finding link</option>{findings.map(f=><option key={f.id} value={f.id}>{f.title}</option>)}</select></label>
        <label className="block"><span className="mb-1.5 block text-xs font-semibold text-[#56635c]">Report file (20 MB max)</span><input className={field} name="file" type="file" accept={accept} required/></label>
        <div className="flex flex-wrap items-center gap-3 md:col-span-2"><button className={btn} disabled={busy}>{busy?'Importing…':'Import report'}</button><span className="text-[10px] text-[#89958d]">Strix SARIF/JSON, Burp XML, and Wireshark CSV get bounded summaries. Original reports remain encrypted; findings are review candidates and are not added automatically.</span></div>
        {error&&<p className="rounded-lg bg-red-50 p-3 text-xs text-red-700 md:col-span-2">{error}</p>}
      </form>
    </Card>
    <Card>
      <div className="border-b border-[#edf1ee] px-4 py-4"><h2 className="text-sm font-semibold">Imported report review</h2><p className="mt-1 text-[10px] text-[#929d96]">Treat scanner ratings as triage evidence; validate findings before assigning risk.</p></div>
      {!imported.length?<div className="px-4 py-6 text-xs text-[#929d96]">No external reports imported yet.</div>:<div className="divide-y divide-[#edf1ee]">{imported.map(item=>{
        const analysis=item.analysis||{}
        return <details key={item.id} className="px-4 py-3"><summary className="flex cursor-pointer flex-wrap items-center gap-2"><b className="text-xs">{item.filename}</b><span className="rounded-full bg-[#edf1f8] px-2 py-1 text-[9px] font-semibold text-[#53698c]">{labels[item.source_tool as SourceTool]||item.source_tool}</span><span className="ml-auto text-[10px] text-[#929d96]">{new Date(item.created_at).toLocaleDateString('en-GB')}</span></summary>
          {analysis.format==='burp_xml_issue_report'&&<><p className="mt-2 text-xs text-[#617168]">{analysis.issue_count} issue(s){analysis.truncated?' (first 500 summarized)':''} · {Object.entries(analysis.severity_counts||{}).map(([level,count])=>`${level}: ${count}`).join(' · ')||'no severity counts'}</p><ul className="mt-2 divide-y divide-[#edf1ee]">{(analysis.issues||[]).slice(0,100).map((issue:any,index:number)=><li key={index} className="py-2"><div className="flex flex-wrap items-center gap-2"><b className="text-xs">{issue.name}</b><span className="text-[10px] text-[#84652e]">{issue.severity} · {issue.confidence}</span></div>{issue.host&&<p className="mt-1 break-all text-[10px] text-[#68776e]">{issue.host}</p>}</li>)}</ul>{analysis.issues?.length>100&&<p className="mt-2 text-[10px] text-[#89958d]">Showing first 100 in this view; full encrypted report remains downloadable below.</p>}<p className="mt-2 text-[10px] text-[#89958d]">{analysis.review_note}</p></>}
          {(analysis.format==='strix_vulnerabilities_json'||analysis.format==='strix_sarif')&&<><p className="mt-2 text-xs text-[#617168]">{analysis.issue_count} candidate finding(s){analysis.truncated?' (summary capped at 500)':''} · {Object.entries(analysis.severity_counts||{}).map(([level,count])=>`${level}: ${count}`).join(' · ')||'no findings reported'}</p><div className="mt-2 divide-y divide-[#edf1ee]">{(analysis.candidates||[]).slice(0,100).map((candidate:any,index:number)=><article key={`${candidate.title}-${index}`} className="py-3"><div className="flex flex-wrap items-center gap-2"><span className="rounded-full bg-[#faf3e5] px-2.5 py-1 text-[10px] font-semibold text-[#9b7b41]">{candidate.severity}</span><b className="text-xs">{candidate.title}</b>{candidate.cvss!=null&&<span className="text-[10px] text-[#87928b]">CVSS {candidate.cvss}</span>}<span className="text-[10px] text-[#87928b]">Confidence: {candidate.confidence}</span></div>{candidate.location&&<p className="mt-1 break-all text-[10px] text-[#68776e]">Location: {candidate.location}</p>}{candidate.cwe&&<p className="mt-1 text-[10px] text-[#68776e]">{candidate.cwe}</p>}{candidate.description&&<p className="mt-1 whitespace-pre-wrap text-xs leading-5 text-[#617168]">{candidate.description}</p>}{candidate.remediation&&<p className="mt-1 text-xs leading-5 text-[#526158]">Suggested remediation: {candidate.remediation}</p>}</article>)}</div>{analysis.candidates?.length>100&&<p className="mt-2 text-[10px] text-[#89958d]">Showing first 100 candidates; full encrypted report remains available below.</p>}<p className="mt-2 rounded-lg bg-[#fffaf0] p-2 text-[10px] leading-4 text-[#84652e]">{analysis.review_note}</p></>}
          {analysis.format==='wireshark_packet_summary_csv'&&<><p className="mt-2 text-xs text-[#617168]">{analysis.packets_summarized} packet row(s) summarized{analysis.total_frame_bytes!=null?` · ${analysis.total_frame_bytes.toLocaleString()} frame bytes`:''}{analysis.truncated?' · summary capped at 50,000 rows':''}</p><div className="mt-2 flex flex-wrap gap-2">{Object.entries(analysis.protocol_counts||{}).map(([protocol,count])=><span key={protocol} className="rounded-full bg-[#f5f8f6] px-2.5 py-1 text-[10px] text-[#526158]">{protocol}: {count as number}</span>)}</div><p className="mt-2 text-[10px] text-[#89958d]">{analysis.review_note}</p></>}
          {analysis.format==='wireshark_capture'&&<p className="mt-2 text-xs leading-5 text-[#617168]">{analysis.note}</p>}
          {analysis.format==='metasploit_xml_inventory'&&<><p className="mt-2 text-xs text-[#617168]">{analysis.host_count} host(s){analysis.truncated?' · summary capped at 500 hosts':''}</p><div className="mt-2 space-y-2">{(analysis.hosts||[]).slice(0,100).map((host:any,index:number)=><div key={index} className="rounded-lg bg-[#f5f8f6] p-2 text-[10px] text-[#526158]"><b>{host.address||'Host address not reported'}</b><p className="mt-1">{(host.services||[]).map((service:any)=>`${service.port}/${service.protocol} ${service.name}`.trim()).join(' · ')||'No services reported'}</p></div>)}</div><p className="mt-2 text-[10px] text-[#89958d]">{analysis.review_note}</p></>}
          {(analysis.format==='password_audit_summary'||analysis.format==='hydra_result_summary')&&<p className="mt-2 rounded-lg bg-[#fffaf0] p-2 text-xs leading-5 text-[#84652e]">{analysis.format==='password_audit_summary'?`${analysis.recovered_entry_count} recovered entries counted from ${analysis.line_count} lines.`:`${analysis.success_count} successful login result(s) counted.`} Secret values are redacted from this summary. {analysis.review_note}</p>}
          {analysis.format==='external_tool_artifact'&&<p className="mt-2 text-xs leading-5 text-[#617168]">{analysis.note} Use the encrypted file in the Evidence objects table below for offline review.</p>}
          <p className="mt-2 text-[10px] text-[#89958d]">SHA-256: {item.sha256}</p>
        </details>
      })}</div>}
    </Card>
  </>
}

function Card({children}:{children:ReactNode}){return <section className="rounded-xl border border-[#e7ede9] bg-white shadow-[0_3px_14px_rgba(22,48,35,.035)]">{children}</section>}
