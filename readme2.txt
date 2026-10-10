PRISM - HOW THE SYSTEM WORKS
=================================

In one sentence
---------------
PRISM takes thousands of separate security log entries, works out which
ones belong to the same attack, and shows that attack as one story: where it
started, what it did, where the attacker is now, and what they might go for
next.


THE PROBLEM IT SOLVES
---------------------
During a real attack, different systems each raise their own small warning:
a login log notices an odd login, a DNS log notices a strange website, an
endpoint log notices PowerShell running. A security team usually sees these
as dozens of unrelated alerts. PRISM connects them.

On the bundled demo data: 56 log entries -> 32 alerts a normal tool would
raise -> 1 connected attack story.


THE PIPELINE, STEP BY STEP
--------------------------

1. INGEST (backend/app/ingest/)
   Reads three kinds of log:
     - Authentication  (Windows Security: who logged into which computer)
     - DNS             (Zeek: which websites each computer looked up)
     - Endpoint        (Sysmon: which programs ran, and what started them)
   Logs come from files at startup or are uploaded through the API.

2. NORMALIZE
   Every log type is converted into ONE common format (NormalizedEvent):
   time, user, source computer, destination computer, process, domain,
   severity. Simple, readable rules flag suspicious behaviour, e.g.
   "Word started PowerShell" or "this domain is on a threat list".
   Some findings need several events: 3+ failed logins in 10 minutes =
   password guessing; the same domain looked up over and over = beaconing.

3. BUILD THE GRAPH (backend/app/graph/)
   Users, computers, programs, domains and events become nodes in a graph
   (NetworkX; optionally copied into Neo4j). Edges record relationships:
   "user LOGGED_INTO computer", "computer EXECUTED program", and so on.
   An inventory file adds context: how important each computer is, who is
   allowed to log in where, which computers can reach which.

4. CORRELATE (backend/app/engine/correlation.py)
   Every pair of suspicious events close in time gets a score from named
   factors: same user, same computer, shared IP, and - the strongest one -
   "a computer that was already compromised was used to reach a NEW
   computer". Time closeness alone can never link two events. Every link
   keeps its reasons, so it can be explained.

5. BUILD ATTACK CHAINS (backend/app/engine/attack_chain.py)
   Events linked by strong scores form groups; each group is one attack
   chain. Nothing is hard-coded: the story comes from the evidence.
   Each chain records its first computer, current computer, stages in time
   order, and which computers were actually reached versus only attempted
   (a failed login proves intent, not access).

6. MAP TO MITRE ATT&CK (backend/app/engine/mitre.py)
   19 rules translate behaviour into the industry-standard ATT&CK
   vocabulary (e.g. T1059.001 PowerShell). Each mapping carries the event
   it came from and a sentence explaining why.

7. DETECT LATERAL MOVEMENT (backend/app/engine/lateral.py)
   A written-out rule: IF a computer showed suspicious activity, AND it was
   then used to log into another computer, AND the same account is
   involved, AND the correlation score is high enough -> lateral movement.
   Every detection lists which conditions passed.

8. PREDICT THE NEXT TARGET (backend/app/engine/prediction.py)
   Plain arithmetic, no machine learning. Six factors are scored and added:
   user access, privilege, graph connectivity, importance, recent activity,
   distance from the attacker. Normalized to 0-100. Always labelled as a
   PREDICTION, never as something that happened.


THE AI AGENT LAYER (backend/app/agents/)
----------------------------------------
On top of the pipeline, nine specialised agents run an investigation when
you press "Start investigation":

   Triage        - is this worth a human's time? (can stop everything here)
   Correlation   - do these alerts really belong together, and why?
   Investigation - forms a hypothesis and checks it step by step
   Evidence      - makes sure every claim points at real log records
   Graph         - who can reach what; how close to critical systems?
   MITRE         - which attack techniques are supported by evidence?
   Chain         - the attack story in time order
   Next Target   - where could the attacker go next, and do the facts hold?
   Verification  - re-checks everything and lowers confidence where the
                   evidence does not hold up

Key rules:
  - Agents cannot state anything they did not fetch through a "tool"
    (17 tools such as search_auth_logs, get_attack_path). This is enforced
    in code: a finding with no evidence is rejected.
  - Agents reuse the pipeline's engines, so they never disagree with the
    dashboard.
  - No AI model (LLM) is required. One is optional and may only rephrase
    already-verified findings; its text is thrown away if it mentions a
    computer or technique that was not verified.
  - The human decides: every finding has Approve / Reject / Mark false
    positive. The system only recommends; it never acts on computers.


HOW TRUST IS KEPT
-----------------
Every statement is labelled with how it was derived:
   OBSERVED   - read directly from a log record
   CORRELATED - several events grouped by shared user/computer/time
   INFERRED   - concluded by a rule (e.g. lateral movement)
   PREDICTED  - a risk estimate, not a fact


THE DASHBOARD (frontend/)
-------------------------
React + Cytoscape.js. The backend decides everything; the screen only draws it.
  - Simple view (default): the attack in plain English in four cards -
    where it started, what it did, where it is now, what might be next -
    plus suggested actions.
  - Analyst view: statistics, the interactive attack graph, the timeline,
    root cause, predictions with score breakdowns, and the agent panels.
  - Simple attack map (default graph in both views): one glowing circle per
    machine plus the attacker's server on the internet, on a dark grid.
    Colours: green = safe, orange = attacked but not taken over, red =
    taken over, pulsing cyan ring = attacker is here now, dashed pink ring
    = might be next (prediction). Moving dots travel along the lines, each
    labelled in plain words ("talking to attacker", "attacker moved",
    "tried to break in", "might go next"). It plays itself step by step;
    beside it are an attack progress bar with Play/Pause/back/forward/End,
    a "Selected machine" box (click any circle), and a live "What is
    happening" log. In the Analyst view, "Attack graph: Simple map /
    Detailed graph" switches to the full technical graph.
  - Clickable statistics: every number card (Investigations, Attack chains,
    Correlated events, Compromised hosts, Lateral movements, Potential
    targets, Alert reduction) opens a panel listing exactly what it counts.
    E.g. "Compromised hosts" lists each host, marks where the attack started
    and where the attacker is now, and notes hosts that were attacked but
    not compromised.
  - Step-by-step playback of the detailed graph: "Play attack step by step"
    starts from an almost empty board and reveals each stage of the attack
    in order, with smooth fades, a camera that glides to the newest step,
    and a plain-English caption ("Stole passwords on HR-PC"). Back / Next /
    progress dots let you move at your own pace; the last step shows the
    predicted next target, clearly labelled as a prediction.
  - Agent panel folds away: once the agents finish, clicking anything in
    the graph slides the agent panel shut so the attack chain and the
    clicked object's details move up into view. Click its header to reopen.
  - Other pages: Investigation, Attack Chains, Events (with log upload),
    MITRE ATT&CK, Hosts, Users.
  - Demo buttons replay the data one event at a time so you can watch the
    attack assemble.


REPORTS
-------
When an investigation is complete, PRISM can produce a report of its
findings:
  - "View report / PDF" (Investigation page, or "Report ->" in the agent
    panel) opens a printable page; its "Print / Save as PDF" button makes
    a PDF.
  - "Download .md" saves the same report as Markdown for tickets or wikis.
The report contains: overview (ID, severity, confidence, times), key facts
(root cause, current host, stage, account, predicted targets, ATT&CK
techniques), the summary split into Observed / Inferred / Predicted,
recommended actions, every finding with its confidence, verification result,
analyst decision and source event IDs, agent activity, and the alert
reduction numbers. It restates what the investigation found and adds no new
claims. API: GET /api/agents/investigations/{id}/report?format=html|md


THE DATA
--------
Two datasets are bundled; choose with PRISM_DATASET:

  synthetic (default) - backend/data/demo/
    Hand-written for this project in real log formats.
    Story: phishing on HR-PC -> PowerShell -> password theft -> RDP to
    FINANCE-PC -> DC01 predicted as next target.

  botsv1 - backend/data/botsv1/
    REAL data from Splunk's public "Boss of the SOC v1" dataset (CC0).
    The Cerber ransomware attack on we8105desk, 24 Aug 2016. 19,672 real
    events. Works end to end but is not yet tuned: it produces too many
    alerts and takes ~47 seconds to analyse. Some inventory facts (such as
    how important each computer is) are assumptions, recorded in
    backend/data/botsv1/MANIFEST.json.

Real-time feed: PRISM can also analyse events as they happen. Other tools
can push events to it (POST /api/live/events), it watches the folder
backend/data/live for new log lines, and scripts/live_windows_collector.ps1
forwards this computer's own Windows events. scripts\live_replay.py streams
the demo attack in real time so you can watch the story build up. The top
bar shows LIVE FEED while events arrive.


HOW TO RUN
----------
Easiest (Windows): double-click "Start PRISM.bat". It checks the computer
(Windows version, memory, disk space) and what PRISM needs (Python, Node.js,
packages). If something is missing it lists what it will install and asks
for your permission first (answer Y or N). No admin rights are needed.
By default everything stays on this computer (local-only / edge mode):
other computers cannot connect, and PRISM sends nothing out and uses no
internet services while running. Optionally (PRISM_LOCAL_ONLY=false) it can
also accept logs from other computers (network mode), from Elastic/Winlogbeat, Splunk (HEC) and syslog, and it can
send its attack alerts to a SIEM (webhook, Splunk or CEF syslog). It also reads
and writes OCSF, the open standard event format (attack chains become OCSF
Detection Findings).
Later launches take a few seconds. The website is protected by an access
code that PRISM creates on first start; the launcher signs you in
automatically. Uploads, live events and investigations are saved, so they
are still there after a restart.
It then asks which data to show: 1 = real-time data from this computer,
2 = the real Splunk BOTS v1 attack recording, 3 = the demo scenario.
After starting, it asks whether PRISM may read this computer's Windows
event logs in real time. Answer N to skip. Logon events need administrator
approval, which Windows asks for separately.

Manual steps:
  python -m venv .venv
  .venv/Scripts/python.exe -m pip install -r backend/requirements-dev.txt
  npm --prefix frontend install
  npm --prefix frontend run build
  .venv/Scripts/python.exe -m uvicorn app.main:app --app-dir backend --port 8000

Open http://localhost:8000     (API documentation: /docs)

SIGNING IN
----------
Default login on first start:  user name Admin, password Admin@123
  (the first sign-in asks you to choose a new password of 12+ characters).
Access code (Access code tab): Start PRISM.bat signs you in automatically;
  otherwise paste the code from backend\data\.prism_token on the computer
  running PRISM. Each installation gets its own random code.

Real BOTS data instead:   set PRISM_DATASET=botsv1 before starting.
Tests (209; 2 need PostgreSQL):       .venv/Scripts/python.exe -m pytest backend/tests -c backend/pytest.ini --rootdir backend
Docker:                   docker compose up -d --build   (then http://localhost:8000)


LIMITATIONS
-----------
  - State lives in memory; restarting clears uploads and investigations
    (so a report must be generated before the server restarts).
  - No login/authentication on the API.
  - Not connected to live log sources.
  - The BOTS dataset path needs tuning before it is demo-ready.


MORE DETAIL
-----------
  README.md             - full project overview
  docs/ARCHITECTURE.md  - design decisions
  docs/AGENTS.md        - the AI agent layer
  docs/API.md           - every API endpoint
  docs/DATASET.md       - the synthetic dataset
  docs/DEMO.md          - a step-by-step presentation script
