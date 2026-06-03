import { useState, useEffect, useRef, useCallback } from 'react';

interface Challenge {
  id: number; name: string; cat: string; pts: number; diff: number; blood: string; solved: boolean;
}

interface Flag {
  val: string; chall: string; time: string;
}

interface LBEntry {
  rank: number; name: string; pts: number; flags: number; me?: boolean;
}

interface Finding {
  sev: string; text: string; time: string;
}

const CHALLENGES: Challenge[] = [
  { id:1,  name:'SQLi Login Bypass',      cat:'WEB',  pts:100, diff:1, blood:'0xal1c3', solved:true  },
  { id:2,  name:'XSS Session Hijack',     cat:'WEB',  pts:200, diff:2, blood:'pwn_m4st', solved:true  },
  { id:3,  name:'SSTI Flask Template',    cat:'WEB',  pts:300, diff:3, blood:'—',        solved:true  },
  { id:4,  name:'JWT Algorithm Confusion',cat:'WEB',  pts:400, diff:4, blood:'—',        solved:false },
  { id:5,  name:'LFI to RCE Chain',       cat:'WEB',  pts:450, diff:4, blood:'—',        solved:false },
  { id:6,  name:'GraphQL Introspection',  cat:'WEB',  pts:500, diff:5, blood:'—',        solved:false },
  { id:7,  name:'Crackme Basic',          cat:'REV',  pts:150, diff:1, blood:'you',      solved:true  },
  { id:8,  name:'Unpack UPX Binary',      cat:'REV',  pts:250, diff:2, blood:'you',      solved:true  },
  { id:9,  name:'Anti-Debug Maze',        cat:'REV',  pts:400, diff:4, blood:'—',        solved:false },
  { id:10, name:'Brainfuck VM',           cat:'REV',  pts:350, diff:3, blood:'—',        solved:false },
  { id:11, name:'Stack BOF x64',          cat:'PWN',  pts:200, diff:2, blood:'you',      solved:true  },
  { id:12, name:'ROP Chain Libc',         cat:'PWN',  pts:500, diff:5, blood:'—',        solved:false },
  { id:13, name:'Heap Use-After-Free',    cat:'PWN',  pts:600, diff:5, blood:'—',        solved:false },
  { id:14, name:'PCAP Analysis',          cat:'FOR',  pts:100, diff:1, blood:'—',        solved:true  },
  { id:15, name:'Volatility Memory Dump', cat:'FOR',  pts:300, diff:3, blood:'—',        solved:true  },
  { id:16, name:'Disk Image Recovery',    cat:'FOR',  pts:350, diff:3, blood:'—',        solved:false },
  { id:17, name:'RSA Small Exponent',     cat:'CRY',  pts:250, diff:2, blood:'—',        solved:true  },
  { id:18, name:'AES-CBC Bit Flip',       cat:'CRY',  pts:400, diff:4, blood:'—',        solved:false },
  { id:19, name:'ECC Twist Attack',       cat:'CRY',  pts:550, diff:5, blood:'—',        solved:false },
  { id:20, name:'Stego LSB PNG',          cat:'MISC', pts:100, diff:1, blood:'—',        solved:true  },
  { id:21, name:'QR Code Mystery',        cat:'MISC', pts:150, diff:2, blood:'—',        solved:true  },
  { id:22, name:'Python Jail Escape',     cat:'MISC', pts:350, diff:3, blood:'—',        solved:false },
  { id:23, name:'Employee OSINT',         cat:'OSINT',pts:200, diff:2, blood:'—',        solved:false },
  { id:24, name:'Exposed Git Repo',       cat:'OSINT',pts:250, diff:2, blood:'—',        solved:false },
];

const FLAGS_INIT: Flag[] = [
  { val:'HTB{s1mpl3_sql1_byp4ss_w0rk3d}', chall:'SQLi Login Bypass',      time:'11:42' },
  { val:'HTB{x55_d0m_s3ss10n_th3ft}',     chall:'XSS Session Hijack',     time:'12:15' },
  { val:'HTB{sst1_r3nd3r_pwn3d_y0u}',     chall:'SSTI Flask Template',    time:'12:51' },
  { val:'HTB{cr4ckm3_t00_34sy}',          chall:'Crackme Basic',          time:'13:07' },
  { val:'HTB{upx_unp4ck3d_l0l}',          chall:'Unpack UPX Binary',      time:'13:28' },
  { val:'HTB{b0f_g4dg3t_f0und}',          chall:'Stack BOF x64',          time:'13:55' },
  { val:'HTB{pcap_t3ll5_s3cr3ts}',        chall:'PCAP Analysis',          time:'14:22' },
  { val:'HTB{v0l4t1l1ty_m4st3r}',         chall:'Volatility Memory Dump', time:'14:44' },
  { val:'HTB{rsa_sm4ll_e_br0k3n}',        chall:'RSA Small Exponent',     time:'15:01' },
];

const LEADERBOARD_INIT: LBEntry[] = [
  {rank:1, name:'0x4l1c3',   pts:6200, flags:18},
  {rank:2, name:'pwn_m4st',  pts:5800, flags:16},
  {rank:3, name:'r3v3rs3r',  pts:5400, flags:15},
  {rank:4, name:'cryptok1ng', pts:5100, flags:14},
  {rank:5, name:'h4x0r404',  pts:4700, flags:13},
  {rank:6, name:'sh3llc0d3', pts:4200, flags:11},
  {rank:7, name:'YOU',       pts:3450, flags:9,  me:true},
  {rank:8, name:'n3tw0rk3r', pts:3100, flags:8},
  {rank:9, name:'f0r3ns1x',  pts:2800, flags:7},
  {rank:10,name:'m1sc_m4n',  pts:2400, flags:6},
];

const FINDINGS_INIT: Finding[] = [
  {sev:'HIGH', text:'SQLi auth bypass on /api/login', time:'11:42'},
  {sev:'HIGH', text:'SSTI → RCE via {{7*7}} on /render', time:'12:51'},
  {sev:'MED',  text:'IDOR /api/users/{id} — all profiles readable', time:'13:20'},
  {sev:'MED',  text:'Redis exposed on :6379 without auth', time:'13:55'},
  {sev:'LOW',  text:'Directory listing on /uploads/', time:'14:10'},
  {sev:'INFO', text:'/.git/config exposed — source leak', time:'14:33'},
];

const TERM_LINES_INIT = [
  {cls:'text-zinc-600', v:'╔═══════════════════════════════════════╗'},
  {cls:'text-zinc-600', v:'║  ITZRAVEN CTF ENGINE v0.0.1              ║'},
  {cls:'text-zinc-600', v:'╚═══════════════════════════════════════╝'},
  {cls:'text-zinc-500', v:''},
  {cls:'text-green-500', v:'[+] CTF mode initialized'},
  {cls:'text-green-500', v:'[+] Agents spawned: recon, exploit, crypto, forensics'},
  {cls:'text-cyan-500',  v:'[*] Event: HackTheBox Season IV  —  284 teams registered'},
  {cls:'text-cyan-500',  v:'[*] Loaded 24 challenges across 7 categories'},
  {cls:'text-green-500', v:'[+] 9 flags already captured  •  3,450 pts  •  rank #7'},
  {cls:'text-zinc-500',  v:''},
  {cls:'text-yellow-400',v:'[!] Exploit agent currently analyzing: Anti-Debug Maze (REV/400)'},
  {cls:'text-cyan-500',  v:'[*] Recon agent scanning: LFI to RCE Chain (WEB/450)'},
  {cls:'text-zinc-500',  v:''},
  {cls:'text-orange-400',v:'itzraven@ctf:~$ '},
];

const LIVE_FEED = [
  {cls:'text-green-500', v:'[+] gobuster found /api/v2/admin — testing...'},
  {cls:'text-yellow-400',v:'[!] JWT alg=none bypass attempt — researching...'},
  {cls:'text-green-500', v:'[+] strings binary | grep HTB — no luck, going deeper'},
  {cls:'text-cyan-500',  v:'[*] Fetching libc version from remote: libc-2.31.so'},
  {cls:'text-green-500', v:'[+] ROP gadget found: 0x4007d3 (pop rdi; ret)'},
  {cls:'text-yellow-400',v:'[!] AES CBC — padding oracle test running (1/256)'},
  {cls:'text-green-500', v:'[+] Crypto agent: small e attack with e=3 confirmed'},
  {cls:'text-cyan-500',  v:'[*] Volatility: dumping process list from memdump.raw'},
  {cls:'text-green-500', v:'[+] Stego: hidden data in LSB of all R channels'},
  {cls:'text-yellow-400',v:'[!] Heap: chunk metadata corrupted — use-after-free pattern'},
  {cls:'text-cyan-500',  v:'[*] OSINT: LinkedIn recon for target employee ongoing'},
  {cls:'text-green-500', v:'[+] GraphQL: __schema introspection returned 47 types'},
  {cls:'text-green-500', v:'[FLAG] Possible flag pattern detected in memory: HTB{...}'},
];

interface Props {
  onClose: () => void;
}

const CAT_COLORS: Record<string, string> = {
  WEB: '#4da6ff', REV: '#b060ff', PWN: '#ff4466',
  FOR: '#39d353', CRY: '#f0c040', MISC: '#3a5068', OSINT: '#ff9944',
};

export default function CtfDashboard({ onClose }: Props) {
  const [flags, setFlags] = useState<Flag[]>([...FLAGS_INIT]);
  const [findings, setFindings] = useState<Finding[]>([...FINDINGS_INIT]);
  const cmdHistoryRef = useRef<string[]>([]);
  const [cmdInput, setCmdInput] = useState('');
  const [catFilter, setCatFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [activeChall, setActiveChall] = useState<number | null>(null);
  const [terminal, setTerminal] = useState<{cls:string;v:string}[]>([...TERM_LINES_INIT]);
  const [elapsed, setElapsed] = useState(0);
  const [timeLeft, setTimeLeft] = useState(4*3600 + 23*60 + 17);
  const [cmdCount, setCmdCount] = useState(0);
  const [toolsCount, setToolsCount] = useState(14);
  const [wrongFlags, setWrongFlags] = useState(2);
  const termRef = useRef<HTMLDivElement>(null);
  const [challenges, setChallenges] = useState<Challenge[]>(CHALLENGES);
  const [bootPhase, setBootPhase] = useState(true);

  const BOOT_STEPS = [
    {pct:10,  msg:'Initializing CTF engine...',       ok:'ctf_engine.so loaded'},
    {pct:22,  msg:'Loading challenge database...',    ok:'24 challenges fetched from API'},
    {pct:35,  msg:'Spawning AI agents...',            ok:'4 agents ready (recon/exploit/crypto/for)'},
    {pct:48,  msg:'Syncing scoreboard...',            ok:'leaderboard: 284 teams, rank #7'},
    {pct:60,  msg:'Restoring session state...',       ok:'9 flags restored  •  3,450 pts'},
    {pct:72,  msg:'Connecting live feed...',          ok:'event stream connected  •  latency 12ms'},
    {pct:85,  msg:'Starting system monitors...',      ok:'CPU/MEM/NET telemetry active'},
    {pct:95,  msg:'Finalizing...',                    warn:'2 unsolved challenges in progress'},
    {pct:100, msg:'CTF MODE READY',                   ok:'welcome back, operator'},
  ];

  useEffect(() => {
    if (!bootPhase) return;
    let step = 0;
    const run = () => {
      if (step >= BOOT_STEPS.length) {
        setTimeout(() => setBootPhase(false), 300);
        return;
      }
      step++;
      setTimeout(run, 150);
    };
    setTimeout(run, 200);
  }, [bootPhase]);

  useEffect(() => {
    if (bootPhase) return;
    const feed = setInterval(() => {
      const l = LIVE_FEED[Math.floor(Math.random() * LIVE_FEED.length)];
      addTermLine(l.cls, l.v);
    }, 7000);
    return () => clearInterval(feed);
  }, [bootPhase]);

  useEffect(() => {
    if (bootPhase) return;
    const timer = setInterval(() => {
      setTimeLeft(t => Math.max(0, t - 1));
      setElapsed(e => e + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [bootPhase]);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [terminal]);

  const addTermLine = useCallback((cls: string, v: string) => {
    setTerminal(t => [...t, { cls, v }]);
    setCmdCount(c => c + 1);
  }, []);

  const solvedCount = challenges.filter(c => c.solved).length;
  const totalScore = challenges.filter(c => c.solved).reduce((s, c) => s + c.pts, 0);
  const firstBloods = challenges.filter(c => c.blood === 'you').length;

  const filteredChalls = challenges.filter(c => {
    if (catFilter !== 'ALL' && c.cat !== catFilter) return false;
    if (statusFilter === 'SOLVED' && !c.solved) return false;
    if (statusFilter === 'OPEN' && c.solved) return false;
    return true;
  });

  const getDiffColor = (d: number) => ['', '#39d353', '#88cc44', '#f0c040', '#ff8c00', '#ff4466'][d] || '#3a5068';

  const handleSubmitFlag = (flag: string) => {
    const valid = /^HTB\{.+\}$/i.test(flag) || /^FLAG\{.+\}$/i.test(flag) || /^CTF\{.+\}$/i.test(flag);
    if (!valid) {
      addTermLine('text-red-400', '[-] Invalid flag format. Expected HTB{...}');
      setWrongFlags(w => w + 1);
      return;
    }
    const unsolved = challenges.find(c => !c.solved);
    if (unsolved && activeChall) {
      solveChallenge(activeChall, flag);
    } else {
      addTermLine('text-green-500', '[+] Flag accepted! +points');
      addFinding('INFO', 'Flag submitted successfully');
    }
  };

  const solveChallenge = (id: number, flagVal?: string) => {
    setChallenges(prev => prev.map(c => {
      if (c.id !== id || c.solved) return c;
      const fval = flagVal || `HTB{4ut0_fl4g_${c.name.replace(/\s/g, '_').toLowerCase()}}`;
      setFlags(f => [{ val: fval, chall: c.name, time: 'now' }, ...f]);
      addTermLine('text-green-500', `[FLAG] ✓ ${c.name} SOLVED — ${fval}`);
      addTermLine('text-green-500', `[+] +${c.pts} points  •  new total: ${totalScore + c.pts}`);
      addFinding('HIGH', `FLAG CAPTURED: ${c.name} (+${c.pts} pts)`);
      setActiveChall(null);
      return { ...c, solved: true };
    }));
  };

  const addFinding = (sev: string, text: string) => {
    const now = new Date();
    const h = String(now.getHours()).padStart(2, '0');
    const m = String(now.getMinutes()).padStart(2, '0');
    setFindings(f => [{ sev, text, time: `${h}:${m}` }, ...f]);
  };

  const processCmd = (raw: string) => {
    addTermLine('text-cyan-400', `itzraven@ctf:~$ ${raw}`);
    const parts = raw.trim().split(/\s+/);
    const cmd = parts[0].toLowerCase();

    if (cmd === '/flag' || cmd === '/submit') {
      const flag = parts.slice(1).join(' ');
      if (!flag) { addTermLine('text-yellow-400', '[!] Usage: /flag HTB{...}'); return; }
      handleSubmitFlag(flag);
    } else if (cmd === '/solve') {
      const name = parts.slice(1).join(' ');
      const c = challenges.find(x => x.name.toLowerCase().includes(name.toLowerCase()) && !x.solved);
      if (c) solveChallenge(c.id);
      else addTermLine('text-yellow-400', `[!] Challenge not found or already solved: ${name}`);
    } else if (cmd === '/run') {
      const tool = parts[1] || 'nmap';
      addTermLine('text-cyan-500', `[*] Running ${tool}...`);
      addFinding('INFO', `Tool invoked: ${tool}`);
      setToolsCount(t => t + 1);
      setTimeout(() => addTermLine('text-green-500', `[+] ${tool} scan complete — check findings panel`), 1500);
    } else if (cmd === '/hint') {
      const c = activeChall ? challenges.find(x => x.id === activeChall) : null;
      if (c) addTermLine('text-cyan-500', `[*] Hint for ${c.name}: Try enumerating with category-specific tools (${c.cat})`);
      else addTermLine('text-cyan-500', '[*] Select a challenge first, then /hint');
    } else if (cmd === '/note') {
      addTermLine('text-cyan-500', `[NOTE] ${parts.slice(1).join(' ')}`);
    } else if (cmd === '/clear') {
      setTerminal([]);
      addTermLine('text-cyan-500', '[*] Terminal cleared');
    } else if (cmd === '/exit' || cmd === '/back') {
      onClose();
    } else if (cmd === '/help') {
      addTermLine('text-cyan-500', 'Commands: /flag HTB{...} | /solve <name> | /run <tool> | /hint | /note <text> | /back | /clear');
    } else {
      addTermLine('text-cyan-500', `[AI] Analyzing: ${raw}`);
      addFinding('INFO', `AI query: ${raw.slice(0, 40)}`);
    }
  };

  const pad = (n: number) => String(n).padStart(2, '0');
  const th = Math.floor(timeLeft / 3600);
  const tm = Math.floor((timeLeft % 3600) / 60);
  const ts = timeLeft % 60;
  const timeStr = `${pad(th)}:${pad(tm)}:${pad(ts)}`;
  const eh = Math.floor(elapsed / 3600);
  const em = Math.floor((elapsed % 3600) / 60);
  const es = elapsed % 60;
  const elapsedStr = `${pad(eh)}:${pad(em)}:${pad(es)}`;

  if (bootPhase) {
    return (
      <div className="fixed inset-0 bg-[#0a0c0f] z-50 flex flex-col items-center justify-center text-[#8ba8c0] font-mono text-xs">
        <pre className="text-[#00d4ff] text-[11px] leading-relaxed text-center mb-4 whitespace-pre">
{`▄▄▄    ██████   ██████  ██    ██ ███████ 
████   ██   ██ ██       ██    ██ ██      
██ ██  ██████  ██   ███ ██    ██ ███████ 
██  ██ ██   ██ ██    ██ ██    ██      ██ 
██   █ ██   ██  ██████   ██████  ███████`}
        </pre>
        <div className="text-[#ff8c00] text-[10px] tracking-[5px] mb-5">◈ CTF MODE INITIALIZING ◈</div>
        <div className="w-[380px] h-[2px] bg-[#1e2d3d] mb-2.5">
          <div className="h-full bg-[#00d4ff] transition-all duration-75" style={{ width: `${Math.min((elapsed / 2), 100)}%` }} />
        </div>
        <div className="text-[#5a7a96] text-[10px] tracking-[1px] h-[14px]">
          {BOOT_STEPS[Math.min(Math.floor(elapsed / 30), BOOT_STEPS.length - 1)]?.msg || 'Initializing...'}
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-[#0a0c0f] z-50 flex flex-col text-[#8ba8c0] font-mono text-xs">
      {/* HEADER */}
      <div className="h-5 bg-[#0d1117] border-b border-[#1e2d3d] flex items-center px-3 gap-0 text-[11px] shrink-0">
        <span className="text-[#00d4ff] font-bold tracking-[2px] mr-2">ITZRAVEN</span>
        <span className="text-[#3a5068] mr-4">v0.0.1</span>
        <span className="text-[#243447] mx-1.5">│</span>
        <span className="text-[#5a7a96]">AUTONOMOUS AI CYBERSECURITY AGENT</span>
        <div className="ml-auto flex items-center gap-0">
          <span className="text-[#5a7a96]">OPERATION:</span>
          <span className="text-[#ff8c00] ml-1 mr-2">CTF</span>
          <span className="text-[#243447] mx-1.5">│</span>
          <span className="text-[#5a7a96] ml-2">EVENT:</span>
          <span className="text-[#00d4ff] ml-1 mr-2">HackTheBox · Season IV</span>
          <span className="text-[#243447] mx-1.5">│</span>
          <span className="text-[#5a7a96] ml-2">SCORE:</span>
          <span className="text-[#00d4ff] ml-1 mr-2">{totalScore.toLocaleString()}</span>
          <span className="w-[6px] h-[6px] rounded-full bg-[#39d353] mr-1.5 animate-pulse" />
          <span className="text-[#39d353]">LIVE</span>
          <span className="ml-3 bg-[rgba(0,212,255,0.08)] border border-[rgba(0,212,255,0.3)] text-[#00d4ff] text-[10px] px-1.5 tracking-[2px] animate-pulse">CTF</span>
        </div>
      </div>

      {/* LAYOUT */}
      <div className="flex flex-1 min-h-0">
        {/* LEFT SIDEBAR */}
        <div className="w-[188px] shrink-0 border-r border-[#1e2d3d] flex flex-col overflow-hidden">
          <div className="border-b border-[#1e2d3d] p-1.5">
            <div className="text-[14px] text-[#00d4ff] font-bold tracking-[1px] mb-0.5">COMPETING</div>
            <div className="text-[10px] text-[#3a5068] mb-1.5">MODE: CTF</div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">Risk Profile</span><span className="text-[#c8dff0]">Aggressive</span></div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">Auto-Exploit</span><span className="text-[#39d353]">ON</span></div>
            <div className="flex justify-between"><span className="text-[#5a7a96]">AI Assist</span><span className="text-[#00d4ff]">ON</span></div>
          </div>

          <div className="border-b border-[#1e2d3d] p-1.5">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">AGENTS [3/4]</div>
            {[
              { name:'Recon', color:'#39d353', status:'Running' },
              { name:'Exploit', color:'#ff8c00', status:'Active' },
              { name:'Crypto', color:'#b060ff', status:'Idle' },
              { name:'Forensics', color:'#3a5068', status:'Standby' },
            ].map(a => (
              <div key={a.name} className="flex justify-between mb-0.5">
                <span style={{color: a.color}}>● {a.name}</span>
                <span className="text-[#c8dff0]">{a.status}</span>
              </div>
            ))}
          </div>

          <div className="border-b border-[#1e2d3d] p-1.5">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">SYSTEM HEALTH</div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">CPU</span></div>
            <div className="bg-[#0a0c0f] border border-[#1e2d3d] h-[5px] mb-0.5"><div className="h-full bg-[#39d353]" style={{width:'42%'}} /></div>
            <div className="flex justify-between mb-1"><span className="text-[#5a7a96] text-[10px]">42%</span></div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">MEM</span></div>
            <div className="bg-[#0a0c0f] border border-[#1e2d3d] h-[5px] mb-0.5"><div className="h-full bg-[#f0c040]" style={{width:'58%'}} /></div>
            <div className="flex justify-between mb-1"><span className="text-[#5a7a96] text-[10px]">58%</span></div>
            <div className="flex justify-between"><span className="text-[#5a7a96]">NET</span></div>
            <div className="bg-[#0a0c0f] border border-[#1e2d3d] h-[5px] mb-0.5"><div className="h-full bg-[#00d4ff]" style={{width:'75%'}} /></div>
          </div>

          <div className="border-b border-[#1e2d3d] p-1.5">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">CTF STATS</div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">Flags</span><span className="text-[#39d353]">{solvedCount} / {challenges.length}</span></div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">Points</span><span className="text-[#00d4ff]">{totalScore.toLocaleString()}</span></div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">1st Blood</span><span className="text-[#ff4466]">{firstBloods}</span></div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">Uptime</span><span className="text-[#c8dff0]">{elapsedStr}</span></div>
            <div className="flex justify-between"><span className="text-[#5a7a96]">Model</span><span className="text-[#c8dff0]" style={{fontSize:'10px'}}>openrouter/z-a…</span></div>
          </div>

          <div className="border-b border-[#1e2d3d] p-1.5">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">BY CATEGORY</div>
            {['WEB','REV','PWN','FOR','CRY','MISC','OSINT'].map(cat => {
              const total = challenges.filter(c => c.cat === cat).length;
              const done = challenges.filter(c => c.cat === cat && c.solved).length;
              const pct = total ? Math.round(done / total * 100) : 0;
              return (
                <div key={cat} className="flex items-center gap-1 mb-0.5">
                  <div className="w-[7px] h-[7px] rounded-sm shrink-0" style={{background: CAT_COLORS[cat]}} />
                  <span className="text-[#5a7a96] w-[38px] text-[11px]">{cat}</span>
                  <div className="flex-1 bg-[#0a0c0f] border border-[#1e2d3d] h-[4px]">
                    <div className="h-full" style={{width:`${pct}%`, background: CAT_COLORS[cat]}} />
                  </div>
                  <span className="text-[#5a7a96] w-[24px] text-right text-[10px]">{done}/{total}</span>
                </div>
              );
            })}
          </div>

          <div className="p-1.5 flex-1 overflow-y-auto">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">RECENT FLAGS</div>
            {flags.slice(0, 6).map((f, i) => (
              <div key={i} className="text-[10px] text-[#39d353] mb-0.5 truncate">
                <span className="text-[#3a5068] mr-1">{f.time}</span>
                {f.val.slice(0, 26)}...
              </div>
            ))}
          </div>
        </div>

        {/* CENTER */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* PIPELINE */}
          <div className="border-b border-[#1e2d3d] px-3.5 pt-1.5 pb-0 shrink-0">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1.5">CTF CHALLENGE PIPELINE</div>
            <div className="relative flex items-center mb-1">
              <div className="absolute left-0 right-0 top-[4px] h-px bg-[#243447] z-0" />
              <div className="absolute left-0 top-[4px] h-px bg-[#00d4ff] z-1 transition-all" style={{width:'37%'}} />
              <div className="flex justify-between w-full relative z-10">
                {['Recon','Web','Rev/Pwn','Forensics','Crypto','OSINT','Misc'].map((name, i) => {
                  const states = ['done','done','active','next','next','next','next'];
                  const state = states[i];
                  return (
                    <div key={name} className="flex flex-col items-center">
                      <div className={`w-[8px] h-[8px] rounded-full border border-[#243447] mb-1 ${
                        state==='done' ? 'bg-[#00d4ff] border-[#00d4ff]' :
                        state==='active' ? 'bg-[#ff8c00] border-[#ff8c00] shadow-[0_0_6px_#ff8c00]' :
                        'bg-[#0a0c0f]'
                      }`} />
                      <div className={`text-[10px] whitespace-nowrap ${state==='done' ? 'text-[#00a8cc]' : state==='active' ? 'text-[#ff8c00]' : 'text-[#3a5068]'}`}>{name}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* AGENT BAR */}
          <div className="flex items-center gap-2.5 px-3.5 py-1 border-b border-[#1e2d3d] shrink-0 text-[11px]">
            <div className="w-[7px] h-[7px] rounded-full bg-[#ff8c00] animate-pulse" />
            <span className="text-[#c8dff0] tracking-[1px]">EXPLOIT AGENT</span>
            <span className="text-[#243447]">●</span>
            <span className="text-[#00d4ff]">RUNNING</span>
            <div className="ml-auto flex gap-2 items-center">
              <select className="bg-[#0d1117] border border-[#243447] text-[#5a7a96] font-mono text-[10px] px-2 py-0.5 outline-none cursor-pointer"
                value={catFilter} onChange={e => setCatFilter(e.target.value)}>
                <option value="ALL">All Categories</option>
                {['WEB','REV','PWN','FOR','CRY','MISC','OSINT'].map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <select className="bg-[#0d1117] border border-[#243447] text-[#5a7a96] font-mono text-[10px] px-2 py-0.5 outline-none cursor-pointer"
                value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
                <option value="ALL">All Status</option>
                <option value="OPEN">Unsolved</option>
                <option value="SOLVED">Solved</option>
              </select>
              <span className="text-[#3a5068] text-[10px]">{elapsedStr}</span>
            </div>
          </div>

          {/* CHALLENGE BOARD + TERMINAL */}
          <div className="flex-1 flex flex-col min-h-0">
            <div className="flex-1 overflow-y-auto p-3 pt-2 space-y-2">
              <div className="grid grid-cols-[22px_1fr_80px_60px_70px_70px_90px] gap-2 px-1.5 pb-1 border-b border-[#1e2d3d] text-[10px] text-[#3a5068] tracking-[1px]">
                <div>#</div><div>CHALLENGE NAME</div><div>CATEGORY</div><div className="text-right">POINTS</div><div>DIFFICULTY</div><div>1ST BLOOD</div><div className="text-right">STATUS</div>
              </div>
              {filteredChalls.map((c, i) => (
                <div key={c.id}
                  className={`grid grid-cols-[22px_1fr_80px_60px_70px_70px_90px] gap-2 px-1.5 py-1 border border-[#1e2d3d] bg-[#0d1117] cursor-pointer transition-colors items-center hover:bg-[#111820] ${
                    c.solved ? 'border-l-2 border-l-[#39d353]' : activeChall === c.id ? 'border-l-2 border-l-[#ff8c00] bg-[#111820]' : ''}`}
                  onClick={() => {
                    if (c.solved) { addTermLine('text-cyan-500', `[*] ${c.name} — already solved (${c.pts} pts)`); return; }
                    setActiveChall(c.id);
                    addTermLine('text-yellow-400', `[!] Switching focus → ${c.name} (${c.cat}/${c.pts} pts)`);
                    addTermLine('text-cyan-500', `[*] Loading tools for category: ${c.cat}`);
                  }}>
                  <div className="text-[#3a5068] text-[10px]">{String(i+1).padStart(2,'0')}</div>
                  <div className={`text-[11px] ${c.solved ? 'text-[#39d353]' : 'text-[#c8dff0]'}`}>{c.name}</div>
                  <div className="text-[10px]" style={{color: CAT_COLORS[c.cat] || '#3a5068'}}>{c.cat}</div>
                  <div className="text-[#ff8c00] text-[11px] text-right">{c.pts}</div>
                  <div className="flex gap-0.5">
                    {Array.from({length:5}, (_, d) => (
                      <div key={d} className="w-[8px] h-[3px] rounded-sm" style={{background: d < c.diff ? getDiffColor(c.diff) : '#243447'}} />
                    ))}
                  </div>
                  <div className="text-[10px] text-[#3a5068]">{c.blood}</div>
                  <div className={`text-[10px] text-right ${c.solved ? 'text-[#39d353]' : activeChall === c.id ? 'text-[#ff8c00]' : 'text-[#3a5068]'}`}>
                    {c.solved ? '✓ SOLVED' : activeChall === c.id ? '⚡ ACTIVE' : '○ OPEN'}
                  </div>
                </div>
              ))}
            </div>

            {/* TERMINAL */}
            <div className="h-[180px] shrink-0 border-t border-[#1e2d3d] flex flex-col">
              <div className="px-3.5 py-0.5 border-b border-[#1e2d3d] flex items-center gap-2.5 text-[10px] shrink-0">
                <div className="w-[7px] h-[7px] rounded-full bg-[#b060ff]" />
                <span className="tracking-[1px] text-[#b060ff]">THINKING</span>
                <span className="text-[#243447]">─</span>
                <span className="text-[#c8dff0]">EXPLOIT AGENT</span>
                <span className="text-[#3a5068] ml-1">(analyzing binary)</span>
                <button className="ml-auto bg-[#0d1117] border border-[#243447] text-[#5a7a96] font-mono text-[10px] px-2 py-0.5 outline-none cursor-pointer hover:border-[#00d4ff] hover:text-[#00d4ff]"
                  onClick={() => { setTerminal([]); addTermLine('text-cyan-500', '[*] Terminal cleared'); }}>CLR</button>
              </div>
              <div ref={termRef} className="flex-1 overflow-y-auto p-3 text-[11px] leading-relaxed bg-[#0a0c0f]" style={{fontSize:'11px', lineHeight:'1.6'}}>
                {terminal.map((l, i) => (
                  <div key={i} className={l.cls}>{l.v}</div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT SIDEBAR */}
        <div className="w-[200px] shrink-0 border-l border-[#1e2d3d] flex flex-col overflow-hidden">
          <div className="border-b border-[#1e2d3d] p-1.5">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">SCORE OVERVIEW</div>
            <div className="text-[22px] font-bold text-[#00d4ff] tracking-[1px] mb-px">{totalScore.toLocaleString()}</div>
            <div className="text-[11px] text-[#ff8c00] mb-1">RANK #7 of 284</div>
            <div className="flex justify-between mb-0.5 text-[11px]"><span className="text-[#5a7a96]">Flags Captured</span><span className="text-[#39d353]">{solvedCount}</span></div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">1st Bloods</span><span className="text-[#ff4466]">{firstBloods}</span></div>
            <div className="flex justify-between mb-0.5"><span className="text-[#5a7a96]">Time Left</span><span className="text-[#ff8c00]">{timeStr}</span></div>
            <div className="flex justify-between"><span className="text-[#5a7a96]">Accuracy</span><span className="text-[#00d4ff]">87%</span></div>
          </div>

          <div className="border-b border-[#1e2d3d] max-h-[200px] overflow-y-auto">
            <div className="p-1.5 pb-0">
              <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1 flex items-center gap-1.5">
                LEADERBOARD <span className="text-[#39d353] text-[9px] border border-[#39d353] px-0.5">LIVE</span>
              </div>
            </div>
            {LEADERBOARD_INIT.map(p => {
              const rankCls = p.rank===1 ? 'text-[#ffd700]' : p.rank===2 ? 'text-[#b0b8c0]' : p.rank===3 ? 'text-[#cd7f32]' : '';
              return (
                <div key={p.rank} className={`flex items-center gap-1 px-2.5 py-0.5 text-[11px] border-b border-[rgba(30,45,61,0.5)] ${p.me ? 'bg-[rgba(0,212,255,0.04)]' : ''}`}>
                  <div className={`w-5 text-[10px] ${rankCls}`}>#{p.rank}</div>
                  <div className={`flex-1 overflow-hidden text-ellipsis whitespace-nowrap ${p.me ? 'text-[#00d4ff]' : 'text-[#5a7a96]'}`}>{p.name}</div>
                  <div className="text-[#39d353] text-[10px]">⚑{p.flags}</div>
                  <div className="text-[#ff8c00] text-[10px]">{p.pts.toLocaleString()}</div>
                </div>
              );
            })}
          </div>

          <div className="border-b border-[#1e2d3d] max-h-[180px] overflow-y-auto">
            <div className="p-1.5 pb-0 flex items-center">
              <div className="text-[10px] text-[#3a5068] tracking-[2px]">KEY FINDINGS</div>
            </div>
            {findings.slice(0, 8).map((f, i) => {
              const sevCls = f.sev==='HIGH' ? 'text-[#ff4466] bg-[rgba(255,68,102,0.15)] border-[rgba(255,68,102,0.3)]' :
                f.sev==='MED' ? 'text-[#ff8c00] bg-[rgba(255,140,0,0.12)] border-[rgba(255,140,0,0.25)]' :
                f.sev==='LOW' ? 'text-[#39d353] bg-[rgba(57,211,83,0.1)] border-[rgba(57,211,83,0.2)]' :
                'text-[#00a8cc] bg-[rgba(0,212,255,0.08)] border-[rgba(0,212,255,0.2)]';
              return (
                <div key={i} className="flex gap-1 px-2.5 py-1 text-[10px] leading-relaxed">
                  <div className={`shrink-0 px-1 rounded-sm text-[9px] ${sevCls}`}>{f.sev}</div>
                  <div className="text-[#8ba8c0] flex-1">{f.text}</div>
                  <div className="text-[#3a5068] shrink-0">{f.time}</div>
                </div>
              );
            })}
          </div>

          <div className="border-b border-[#1e2d3d] p-1.5">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">SESSION METRICS</div>
            {[
              ['Commands Executed', cmdCount.toString(), '#00d4ff'],
              ['Flags Submitted', solvedCount.toString(), '#39d353'],
              ['Wrong Flags', wrongFlags.toString(), '#ff4466'],
              ['Tools Invoked', toolsCount.toString(), '#c8dff0'],
              ['Time Elapsed', elapsedStr, '#c8dff0'],
            ].map(([lbl, val, color]) => (
              <div key={lbl as string} className="flex justify-between py-0.5 text-[11px] border-b border-[rgba(30,45,61,0.4)]">
                <span className="text-[#5a7a96]">{lbl as string}</span>
                <span style={{color}}>{val as string}</span>
              </div>
            ))}
          </div>

          <div className="p-1.5 flex-1">
            <div className="text-[10px] text-[#3a5068] tracking-[2px] mb-1">CHALLENGE DIFFICULTY</div>
            <div className="text-[20px] text-[#ff8c00] font-bold">6.4</div>
            <div className="text-[10px] text-[#3a5068] mb-2">Hard Average</div>
            <div className="flex justify-between py-0.5 text-[11px]"><span className="text-[#5a7a96]">Easiest solved</span><span className="text-[#39d353]">100 pts</span></div>
            <div className="flex justify-between py-0.5 text-[11px]"><span className="text-[#5a7a96]">Hardest solved</span><span className="text-[#ff8c00]">500 pts</span></div>
            <div className="flex justify-between py-0.5 text-[11px]"><span className="text-[#5a7a96]">Next target</span><span className="text-[#00d4ff]">
              {activeChall ? challenges.find(c => c.id === activeChall)?.name : 'Select a challenge'}
            </span></div>
          </div>
        </div>
      </div>

      {/* COCKPIT BAR */}
      <div className="h-[22px] shrink-0 bg-[#0d1117] border-t border-[#1e2d3d] flex items-center px-2.5 gap-2">
        <span className="text-[#00d4ff] whitespace-nowrap text-[12px]">itzraven<span className="text-[#ff8c00]">@ctf</span>:~$</span>
        <input type="text" value={cmdInput}
          onChange={e => setCmdInput(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && cmdInput.trim()) {
              cmdHistoryRef.current = [...cmdHistoryRef.current, cmdInput.trim()];
              processCmd(cmdInput.trim());
              setCmdInput('');
            }
          }}
          placeholder="Type command or ask AI...  [ /flag HTB{...} | /run nmap | /solve <name> | /back ]"
          className="flex-1 bg-transparent border-none outline-none text-[#00d4ff] font-mono text-[12px] placeholder-[#3a5068]"
          autoFocus
        />
        <div className="flex gap-2 shrink-0">
          <button className="bg-[#0a0c0f] border border-[#1e2d3d] text-[#3a5068] text-[10px] px-1.5 cursor-pointer hover:border-[#243447] hover:text-[#5a7a96]"
            onClick={() => setCmdInput('/flag ')}>? Flag</button>
          <button className="bg-[#0a0c0f] border border-[#1e2d3d] text-[#3a5068] text-[10px] px-1.5 cursor-pointer hover:border-[#243447] hover:text-[#5a7a96]"
            onClick={() => onClose()}>← Back</button>
        </div>
      </div>
    </div>
  );
}
