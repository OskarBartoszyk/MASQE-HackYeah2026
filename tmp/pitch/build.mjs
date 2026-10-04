import fs from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {Presentation, PresentationFile} from '@oai/artifact-tool';
import sharp from 'sharp';

const ROOT='/Users/oskar/Desktop/HackYeah2026';
const TMP=ROOT+'/tmp/pitch';
const OUT=ROOT+'/output/presentation';
const SKILL='/Users/oskar/.codex/plugins/cache/openai-primary-runtime/presentations/26.905.11957/skills/presentations';
const {finalizePresentation,resolvePresentationFont}=await import(pathToFileURL(SKILL+'/container_tools/artifact_tool_utils.mjs').href);
await fs.mkdir(OUT,{recursive:true});
const font=resolvePresentationFont({fontFamily:'Arial'});
const C={ink:'#171D20',cream:'#F6F6F1',green:'#35735B',sage:'#E2E9DB',muted:'#66716B',rust:'#A84031',white:'#FFFFFF'};
const p=Presentation.create({slideSize:{width:1280,height:720}});
const notes=[];
function text(s,str,x,y,w,h,size=26,color=C.ink,bold=false){
  const a=s.shapes.add({geometry:'textbox',name:str.slice(0,45),position:{left:x,top:y,width:w,height:h},fill:'none',line:{fill:'none',width:0}});
  a.text=str;
  a.text.style={typeface:font,fontSize:size,bold,color,alignment:'left',verticalAlignment:'top',autoFit:'none',wrap:'square',insets:{top:0,bottom:0,left:0,right:0}};
  return a;
}
function slide(title,dark=false){
  const s=p.slides.add();s.background.fill=dark?C.ink:C.cream;
  if(title)text(s,title,64,48,1145,70,46,dark?C.cream:C.ink,true);
  text(s,String(p.slides.items.length).padStart(2,'0'),1170,666,50,25,16,dark?C.sage:C.muted);
  return s;
}
function note(s,title,time,script,sources){
  const n=`${title}\nTiming: ${time}\n\n${script}\n\nSources:\n${sources.map(x=>'- '+x).join('\n')}`;
  s.speakerNotes.textFrame.setText(n);notes.push({title,time,script});
}
function node(s,title,body,x,y,w,h,fill=C.white){
  const box=s.shapes.add({geometry:'rect',name:title,position:{left:x,top:y,width:w,height:h},fill,line:{fill:C.muted,width:1}});
  text(s,title,x+22,y+20,w-44,40,27,C.ink,true);
  text(s,body,x+22,y+68,w-44,h-80,22,C.muted);
  return box;
}
function connect(s,a,b,from='right',to='left'){
  s.shapes.connect(a,b,{kind:'elbow',fromSide:from,toSide:to,line:{fill:C.green,width:2.5},head:{type:'arrow',width:'med',length:'med'}});
}

// 1. Preserve the existing project mark, with no synthesized decoration.
{
const s=slide('',true);
const logo=await sharp(ROOT+'/dashboard/public/masqe.svg').resize(540,540).png().toBuffer();
s.images.add({blob:logo,contentType:'image/png',alt:'MASQE project logo',fit:'contain',position:{left:884,top:190,width:260,height:260}});
text(s,'MASQE',64,164,780,130,104,C.cream,true);
text(s,'AI Control Layer',69,310,760,65,43,C.sage);
text(s,'Security and governance for agents that take action',69,417,680,110,31,C.cream);
text(s,'HackYeah 2026',69,625,450,28,20,C.sage);
note(s,'MASQE','0:00–0:15',
`MASQE is an AI control layer for agents that can access data and use tools. It checks what an agent wants to do, applies the organisation’s policy, and records the outcome so people can understand and review it.`,['README.md','dashboard/public/masqe.svg','/Users/oskar/Desktop/instruction.pdf']);
}
// 2. One concrete task explains the risk better than a threat taxonomy.
{
const s=slide('The risk begins when an agent takes action');
text(s,'“Review this repository.”',64,163,1110,70,44,C.green,true);
text(s,'A legitimate request can lead the agent into instructions hidden in untrusted files.',64,254,1050,90,31);
text(s,'Untrusted input',64,404,460,40,29,C.ink,true);
text(s,'README files, retrieved documents\nand tool responses',64,457,480,100,26,C.muted);
text(s,'Potential damage',682,404,480,40,29,C.ink,true);
text(s,'Stolen credentials, unsafe commands\nand uncontrolled resource use',682,457,500,100,26,C.muted);
note(s,'The risk','0:15–0:40',
`Consider a normal request: review this repository. The repository contains a README, and that README can contain instructions written by someone else. If the agent treats those instructions as authority, a code review can become an attempt to read credentials or send data outside the organisation. MASQE puts a policy decision between the agent’s request and the action.`,['/Users/oskar/Desktop/instruction.pdf','ai-guard/ghost.py','tests/e2e_test.py']);
}
// 3. Native architecture diagram: the requested architecture evidence.
{
const s=slide('One enforcement point');
const client=node(s,'Apps and agents','API, Python SDK\nand MCP tools',64,258,280,166);
const gate=node(s,'Go gateway','Identity, policy, budgets\nFinal decision',430,258,340,166,C.sage);
const target=node(s,'Tools and models','Approved action\nOutput checked on return',856,258,360,166);
const guard=node(s,'Python AI Guard','Semantic risk scores',430,498,340,133);
connect(s,client,gate);connect(s,gate,target);connect(s,gate,guard,'bottom','top');
text(s,'Central policy and threat feeds',430,167,550,40,26,C.green,true);
text(s,'Every decision produces an audit event.',64,568,300,76,24,C.muted);
text(s,'Ghost Shell receives\nuntrusted shell work.',856,514,350,80,26,C.green,true);
note(s,'Architecture','0:40–1:15',
`Applications connect through an API, a Python SDK or an MCP wrapper. The Go gateway owns the final decision. It checks identity, permissions, policy and budgets, and asks the Python AI Guard for semantic risk scores when needed. Approved requests reach tools or models, and the gateway checks their output before returning it. Untrusted shell work goes to Ghost Shell. Policy and threat feeds remain separate from application code.`,['docs/architecture.svg','gateway/gateway.go','README.md']);
}
// 4. Flat editorial composition, not a grid of UI cards.
{
const s=slide('Rules and AI assess different risks');
text(s,'Deterministic controls',64,162,525,52,32,C.green,true);
text(s,'Who may act, on which resource?\nDoes the request contain a secret?\nHas it exceeded its budget?',64,236,525,155,28);
text(s,'Semantic controls',680,162,536,52,32,C.green,true);
text(s,'Does the text try to override instructions?\nDoes the action drift from the task?\nDoes it try to poison agent memory?',680,236,536,170,28);
text(s,'Proportionate responses',64,476,600,44,31,C.ink,true);
text(s,'Allow or redact. Route to Ghost Shell or request approval.\nThrottle or block when policy requires it.',64,536,1130,86,29,C.muted);
note(s,'Hybrid controls','1:15–1:45',
`The controls combine explicit rules with local semantic detection. Rules handle facts such as permissions, secrets and budget limits. The AI Guard adds signals for instruction override, task drift and malicious content in memory. The gateway can allow, redact, isolate, request approval, throttle or block. This gives us more than a single yes-or-no filter. Optional Polish PII detection uses the existing local model and needs Polish-language validation.`,['README.md','ai-guard/server.py','ai-guard/ner_service.py','policies/policy.yaml']);
}
{
const s=slide('Policy changes take effect while MASQE runs');
text(s,'Change the configuration',64,165,780,50,35,C.green,true);
text(s,'Permissions, allowed models, risk thresholds and threat signatures',64,228,1120,74,28);
text(s,'Control consumption',64,340,780,50,35,C.green,true);
text(s,'Token and cost budgets, request rates, tool calls and runtime',64,403,1120,74,28);
text(s,'Invalid edits keep the last valid configuration active.',64,553,1110,68,29,C.muted);
note(s,'Live configuration','1:45–2:15',
`The jury can change policy and threat feeds while the services are running. That includes permissions, allowed models and risk thresholds. Resource controls cover tokens, estimated cost, request rates, tool calls and runtime. Changes affect subsequent decisions, and invalid configuration keeps the last valid snapshot active. The console exposes the policy version and consumption, so the result of a configuration change can be observed rather than simply claimed.`,['policies/policy.yaml','policies/threat-feed.yaml','tests/e2e_test.py','README.md']);
}
{
const s=slide('Ghost Shell: an attack without host execution',true);
const rows=[
['01','Read the repository','A README contains a malicious setup instruction.'],
['02','Run the “installer”','The emulator returns a simulated result.'],
['03','Read the fake .env','Per-session honeytokens act as marked credentials.'],
['04','Attempt an upload','MASQE detects the tokens and records an incident.']
];
for(let i=0;i<rows.length;i++){
  const y=155+i*105;
  text(s,rows[i][0],64,y,70,48,34,C.sage,true);
  text(s,rows[i][1],164,y,990,43,31,C.cream,true);
  text(s,rows[i][2],164,y+43,1040,46,25,C.sage);
}
text(s,'No host command or outbound network request runs. The recorder preserves a hash chain.',64,615,1120,52,23,C.sage);
note(s,'Ghost Shell','2:15–3:05',
`Ghost Shell is the main demonstration. An agent reads a repository whose README contains a malicious setup instruction. It appears to download and run an installer, but our deterministic Python emulator only returns a simulated result. The agent then reads a fake environment file containing marked credentials called honeytokens. When it tries to upload that file, MASQE detects the markers and records a confirmed exfiltration attempt. No command runs on the host and no outbound network request is sent. The recorder links commands and responses with hashes, which lets us verify the chain. This is an analysis environment. Legitimate commands are simulated too, so it does not replace a real CI system.`,['ai-guard/ghost.py','ai-guard/test_ghost.py','tests/e2e_test.py::test_20_ghost_shell_attack_and_isolation']);
}
{
const s=slide('A console for security and management');
text(s,'Security teams',64,165,530,50,35,C.green,true);
text(s,'Live decisions and incidents\nTriggered controls and audit records\nGhost Shell command history',64,248,530,170,28);
text(s,'Management',685,165,530,50,35,C.green,true);
text(s,'Resource use and budget status\nLatency percentiles\nExportable reports',685,248,530,170,28);
text(s,'Optional AI explanations translate the verdict into plain language.',64,514,1138,85,31,C.ink,true);
text(s,'The local explainer currently answers in Polish and runs after the security decision.',64,615,1138,40,23,C.muted);
note(s,'Operations console','3:05–3:40',
`The operations console serves both security and management. Security teams can move from an incident to the triggering controls and the event trail. Management can see resource use, budget status and latency, and export reports. An optional local language model adds plain-language explanations after the verdict, without deciding whether the action is allowed. That explainer currently answers in Polish. If its model is unavailable, MASQE reports that honestly instead of presenting a fabricated explanation.`,['dashboard/src/App.jsx','ai-guard/explain.py','README.md']);
}
{
const s=slide('Evidence the jury can challenge');
text(s,'159',64,160,520,160,124,C.green,true);
text(s,'automated tests passed',68,323,550,49,33,C.ink,true);
text(s,'Verified run: 4 October 2026',68,385,540,43,23,C.muted);
text(s,'Positive and negative cases',685,164,520,45,30,C.ink,true);
text(s,'Safe requests proceed. Unsafe actions\ntrigger the configured response.',685,221,520,93,26,C.muted);
text(s,'Real services, live changes',685,355,520,45,30,C.ink,true);
text(s,'HTTP flows, policy reload, Ghost Shell,\nAPI integrations and failure handling',685,412,520,97,26,C.muted);
text(s,'Try an ad-hoc prompt. Change a rule. Inspect the decision and telemetry.',64,568,1138,78,29,C.green,true);
note(s,'Test evidence','3:40–4:10',
`The verified full run passed 159 automated tests. The suite includes positive cases that must remain usable and negative cases that must trigger controls. End-to-end tests start the real Go and Python services and exercise HTTP requests, live configuration changes, integrations and failure behaviour. For evaluation, the jury can enter a new prompt, change a rule, and inspect the decision and telemetry. This is functional evidence, not a claim that every possible attack is detected.`,['Verified make test run in the project review, 4 October 2026: 159 passed, 0 failed.','Makefile','tests/e2e_test.py','ai-guard/test_ghost.py','README.md']);
}
{
const s=slide('MASQE today',true);
text(s,'A working local control layer',64,169,1100,72,44,C.cream,true);
text(s,'Gateway and integrations\nLive policy, budgets and reporting\nGhost Shell with traceable attack evidence',64,291,1080,171,33,C.sage);
text(s,'Next: broader adversarial evaluation and production hardening',64,534,1120,70,27,C.sage);
text(s,'github.com/OskarBartoszyk/MASQE-HackYeah2026',64,639,1060,31,22,C.cream);
note(s,'Closing','4:10–4:35',
`MASQE already combines a working local gateway, several integration paths, live policy and resource controls, and a console for reviewing decisions. Ghost Shell adds a safe way to observe an agent’s attack sequence. The prototype runs without a paid API. The next work is broader adversarial evaluation and production hardening, including live-model validation. The repository contains setup instructions and the test commands. We are ready to demonstrate the system and let the jury challenge it.`,['README.md','Makefile','docker-compose.yml','git remote origin']);
}
if(p.slides.items.length!==9)throw new Error('Expected nine slides');
await (await PresentationFile.exportPptx(p)).save(TMP+'/candidate.pptx');
await fs.writeFile(OUT+'/MASQE-speaker-notes.md','# MASQE: five-minute pitch\n\nNine slides. Planned duration: 4 minutes 35 seconds, leaving 25 seconds for transitions.\n\n'+notes.map((n,i)=>`## ${i+1}. ${n.title} (${n.time})\n\n${n.script}\n`).join('\n')+'\n## Submission reminder\n\nThe competition rules require the team name and team-member list. Add the confirmed details to the title slide before submission. Do not assume that the repository owner represents the complete team.\n\n## Demonstration boundaries\n\nGhost Shell emulates commands and network activity. The optional explainer currently responds in Polish. The automated suite does not establish live model accuracy or production readiness.\n');
const result=await finalizePresentation({workspaceDir:ROOT,candidatePath:TMP+'/candidate.pptx',finalPath:OUT+'/MASQE-jury-pitch.pptx',pythonExecutable:'/Users/oskar/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3',integrityValidatorPath:SKILL+'/container_tools/inspect_presentation_package_integrity.py',layoutValidatorPath:SKILL+'/container_tools/inspect_presentation_layout_geometry.py',layoutArgs:['--expected-slide-size-emu','12192000,6858000','--validate-bullet-geometry','--validate-heading-fit'],requiredNativeTableOwnerSlides:[],requiredNativeChartOwnerSlides:[],fontPolicy:{basis:'design',families:[font]},verifyArtifactToolImport:true,receiptPath:TMP+'/validation.json'});
console.log(JSON.stringify(result));
