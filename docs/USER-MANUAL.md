# Tempra RMM — Operator Manual

## 1. Introduction

Tempra RMM (TEMPRA Endpoint Monitoring, Patching & Remote Administration) lets you monitor, patch and operate Windows and Linux computers from a web console. This manual is for operators who use the console every day; installation of the server is covered in `docs/INSTALL.md`.

### Key concepts

| Term | Meaning |
| --- | --- |
| Console | The web application you sign in to. It may be a customer console or a central console that operates several linked customer consoles. |
| Agent | The service installed on each computer. It always connects out to the console; the console never connects to a PC. |
| Client / Server | Computers are split by Windows installation type (workstation or server). Each has its own view. |
| Site | A location defined by its subnets. A computer belongs to the first site that contains one of its IP addresses. |
| Group | A personal or public list of computers or users, used to filter and to run actions on many computers. |
| Job | One signed command sent to one agent (a script, an update, an installation). Every job has a validity window. |
| Module | A signed plugin that gives the agent a feature (inventory, Windows Update, firmware, files, screen...). |
| Policy | Signed recurring work the agents run on their own schedule (scans, collections, reboots in a window). |
| Workflow | A software distribution recipe: detection rules plus ordered, conditional steps. |
| Check / Alert | A check is a status (ok, warning, failing) reported by a module. A failing check, or an unusual logon, raises an alert. |

### Roles

Your role comes from Microsoft Entra ID and decides what you can do.

| Role | Can do |
| --- | --- |
| Reader | See every page, report and dashboard. Cannot run anything. |
| Operator | Everything a Reader can, plus run commands, scripts, shell, remote control, file transfers, installations and updates (each approved with MFA); approve new agents; edit workflows, groups and provisioning profiles; acknowledge alerts; start provisioning. |
| Admin | Everything an Operator can, plus revoke agents; upload packages; approve policies, modules, permanent workflow assignments and provisioning profiles; manage sites, tokens, settings, agent versions and installers. |

### The golden rule: every action is approved with MFA

The agents run only commands signed by a separate signing service, and that service signs only after you sign in again to Microsoft with MFA for that exact command. Expect a Microsoft sign-in window each time you launch an action. Read-only collections (inventory, scans) run without a new sign-in.

## 2. Getting started

### Signing in

1. Open the console address your administrator gave you (it is reachable only from the company LAN or VPN).
2. Sign in with your Microsoft 365 account. MFA is mandatory; the console never sees your password.
3. If you see an access error, ask an administrator to assign you a Tempra RMM role in Entra ID.

Sessions expire after a period of inactivity and after a maximum lifetime; sign in again when asked.

### Approving an action (step-up)

When you launch any command, a Microsoft sign-in opens for that command. Sign in as yourself and complete MFA. The approval is bound to the exact command, computers and parameters you reviewed; it cannot be reused for anything else. If you close the window, nothing is sent.

### The screen layout

- **Header**: the menu, the open-alerts badge, the language selector (Italian / English) and the light/dark theme.
- **Left column** (agent lists): the site tree, then the Active Directory OUs when AD is integrated. A click filters the list.
- **Main area**: the page content. Pages with a **?** next to the title open a short contextual help.
- **Bottom-right box**: your jobs in progress, on every page.

### The menu

| Menu | Items |
| --- | --- |
| Agents | Clients, Servers, All agents, Groups |
| Jobs | Every command sent, with status and result |
| Patch | Update dashboard (Windows, Linux, applications, firmware) |
| Software | Library, Workflows |
| Provisioning | Profiles, Runs |
| Deployment | Installer, Agent versions, Modules, Policy |
| Reporting | Reporting, Alerts, Activity |
| Security | Dashboard, Vulnerabilities |
| Administration | Settings, Setup, Scopes (OpenRMM.Admin only) |
| Linked consoles | Only on a federated console |

## 3. Enrolling computers

A computer joins the console in two steps: the agent is installed and enrolls with a token, then an operator approves it. Until approved, it is visible but receives no commands.

### Getting the installer

**Deployment → Installer** (Admin builds, Operator downloads) produces an installer already configured for this console: console address, root certificate, public keys and an enrollment token.

| Platform | File | How to install |
| --- | --- | --- |
| Windows | `openrmm-agent-x.y.z.msi`, Authenticode-signed | Double click, `msiexec /i <file> /qn`, or assign it in a Group Policy (Software installation → Assigned) |
| Linux x86\_64 / ARM64 | `openrmm-agent-x.y.z-linux-amd64.run` | `sudo sh <file>`; compare the SHA-256 shown in the console first. Needs systemd. |

With a dedicated code-signing CA, deploy `codesign-ca.cer` (Trusted Root) and `codesign.cer` (Trusted Publishers) by Group Policy before the MSI; the links are on the Installer page.

### Group Policy settings

The ADMX templates (**Computer Configuration → Administrative Templates → Tempra RMM**) can also set the console address and token, and three local switches the console can never override:

| Setting | Default | Effect |
| --- | --- | --- |
| AllowAdHocScripts | On | Off = the computer refuses scripts and workflows sent from the console |
| AllowInteractiveShell | Off | On = remote shell sessions allowed |
| AllowRemoteControl | Off | On = remote control of the screen allowed |

### Approving new computers

1. Open **Agents → All agents**; new computers show as *pending*.
2. Check that you recognize the name and the address. Approve only computers you expect.
3. Select one or several and choose **Approve**.

### Enrollment tokens

**Deployment → Installer → Tokens for manual installations** (Admin) lists the tokens. A token lets an agent present itself, never approve itself (unless a token was explicitly created with auto-approval). Give tokens an expiry and a use limit close to the number of PCs, and **revoke a token at once if an installer leaks**.

### Removing a computer

An Admin can **Revoke** an agent from its page: it is disconnected immediately and can no longer connect. Uninstall the agent from the computer with Programs and Features or `msiexec /x`.

## 4. Working with agents

The agent list is the home page: every computer, its status at a glance, and the starting point for any action.

### The agent list

- **Clients / Servers / All agents** in the Agents menu split the fleet by Windows installation type.
- **Filters** on the left: site, operating system, Active Directory OU; a row of state filters with counts (online, offline, serious issues, any issue, missing patches, pending reboot, apps to update). Selecting a group shows only its computers.
- **Search** finds by name, IP, logged-on user, model, serial, agent version or remote-access ID (Supremo, AnyDesk, TeamViewer). Use `*` as a wildcard.
- **Status icons** show online/offline, open alerts, failing checks, missing patches, pending reboot and outdated applications. Drag a column's header edge to resize it (double click resets); widths are remembered per browser.
- **Click** a computer to open the bottom panel; **right-click** for the quick menu (commands, shell, remote control, files, workflows).
- **Tick several computers** to run one action on all of them with a single MFA approval (see section 5).

### The agent panel and page

The bottom panel and the full agent page show the same tabs:

| Tab | What you find |
| --- | --- |
| Summary | OS, model, serial, logged-on user, IP, site, OU, ring, agent version, last contact |
| Checks | Every check with its status (ok, warning, failing) and summary |
| Patches | Missing Windows/Linux updates, blockers, winget upgrades, firmware, logs of failed updates |
| Software | Installed applications, with **Uninstall…** where a silent removal is possible |
| Inventory | Hardware, BIOS, disks and their health, BitLocker, battery, TPM, network, monitors |
| Logons | Local and RDP logons, failures and lockouts, kept 90 days |
| Policies | Results of the policy rules on this computer |
| History | Changes over time: software installed/removed/updated, memory, disks, BIOS, OS build, BitLocker |
| Notes | Free notes, with author and date (audited) |
| Commands | Run a command or script, open shell, remote control or file management |

### Sites

A computer goes automatically into the first site whose subnets contain one of its IP addresses. You can also move one or more computers to a site by hand from the panel or the bulk actions. Sites and subnets are defined by an Admin in **Settings**.

### Groups

**Agents → Groups** holds groups of computers or of users.

- A **personal** group is visible only to you; a **public** one to every operator.
- A **user group** targets the computers where those users are logged on, or were last seen within the days you set.
- From a group page you can launch commands, scripts, installations and workflows on all its members with one MFA approval. Only approved computers receive them.

## 5. Remote actions

Every remote action is approved with MFA and recorded in the Activity log with your name. Sessions (shell, screen, files) are time-limited and usable only by the operator who approved them.

| Action | Approval | Time limit | Requirements |
| --- | --- | --- | --- |
| Command or script (PowerShell / sh) | MFA per command | Job validity 15 min – 48 h | AllowAdHocScripts not 0 |
| Interactive shell | MFA per session | Up to 60 min (default 30); closes after 15 min idle | GPO AllowInteractiveShell on; one computer |
| Remote control | MFA per session | Up to 60 min | Windows; GPO AllowRemoteControl on; a logged-on, unlocked user; `screen` module published |
| File management | MFA per session | Up to 240 min (default 60) | Agent 1.1.0+; `files` module published |

### Running a command or script

1. On the agent page (Commands tab) or in the bulk form, pick the module and action, e.g. *script · run*, and fill the parameters.
2. Choose the validity: a computer that is off for longer never runs the job and it ends as *expired*.
3. Click run and approve with MFA. The full script text is stored in the audit log.
4. Follow it in the bottom-right box or in **Jobs**.

### Interactive shell

Opens PowerShell (bash on Linux) in a terminal in the browser. Every line you type is recorded in the audit log; the output is not. Close the session when done.

### Remote control

Shows the user's screen and lets you move mouse and keyboard. It opens in a new browser tab. The console warns you if no user appears logged on or the screen is locked. Tell the user before you connect.

### File management

- **Browse** picks the computer whose folders you see; **Apply to** chooses the computers to upload to, or download from as one zip with a folder per computer.
- The agent's own folders are never accessible. An existing file is replaced only if you ask.
- The maximum file size is set by the Admin (default 1 GB). Every file transferred is audited with its SHA-256.

### Bulk actions

Tick computers in the agent list (or open a group) and choose an action: command, script, package installation, workflow, file management, site or update ring. One MFA approval covers up to 500 computers; each receives its own signed job. Only actions available on every selected platform are offered.

### Jobs

**Jobs** lists every command with its status. *Completed with errors* means the module ran but some items (an update, an application) failed: open the job for details, parameters, progress and the module log. Filter by computer or search by module, action and status.

## 6. Patches and software

The **Patch** dashboard ranks computers by how far behind they are, so you fix the worst first. Modules never reboot on their own: reboots happen in the maintenance windows of the reboot policy.

### The Patch dashboard

- Computers ranked by an update score: missing security updates and their age (days and Patch Tuesdays), other updates, pending reboot and for how long, outdated applications.
- Compliance counters and the most widespread outdated applications ("Chrome outdated on 37 PCs"), with **Update…** to fix one application everywhere with one approval.
- Filters for Clients / Servers, site and group.
- Sources: Windows Update (apt, dnf, zypper on Linux), applications via winget or the console catalog, firmware via the vendor tools.

### Windows Update on one computer

The agent's **Patches** tab shows missing updates, the last installation, the pending reboot and who manages updates.

- **WSUS or Intune managed**: Tempra RMM only observes; it does not install unless a policy explicitly allows it.
- **Blockers**: settings that stop updates (pinned release, unreachable WSUS server, disabled services, pauses, low disk space). Fix them on the computer or in the GPO; **Free space…** clears the Windows Update cache and runs Disk Cleanup.
- **Logs**: one click collects the last 7 days of update logs; the full collection is a command with MFA. Failed installations show the explained error code.
- **Install**: choose classifications (security and critical by default), include or exclude KBs, approve with MFA. The computer is not rebooted.

### Firmware, BIOS and drivers

On Dell, Lenovo and HP the `firmware` module uses Dell Command Update, Lenovo System Update or HP Image Assistant. **Install tool…** installs the vendor tool if missing. When installing, pick the types and importance; the **BIOS is installed only if ticked**, on mains power with at least 50% battery, and BitLocker is suspended for one reboot.

### Software library

**Software → Library** holds the installers (MSI, EXE with silent switches) that an Admin uploads or imports from the winget catalog.

1. Open a package and choose **Deploy**.
2. Pick the computers: those with an older version are preselected.
3. Approve once with MFA. Each agent downloads the package from the console and checks its SHA-256 and Authenticode signature before installing. Unsigned packages must be explicitly allowed by an Admin.

Computers that are off receive the job when they reconnect, within its validity (24 h by default for deployments).

### Uninstalling an application

In the agent's **Software** tab, choose **Uninstall…** on an application and approve with MFA. The removal is silent and verified afterwards. Per-user installations and the Tempra RMM agent cannot be removed this way.

### Upgrading an application on many computers

From the Patch dashboard, a report search or a vulnerability, **Update…** opens the winget upgrade already prepared: choose the site, review the list and approve once. The console catalog also detects outdated software where winget is not available (e.g. Windows Server 2019) and distributes the installer from the library.

## 7. Workflows, policies, modules and agent versions

Workflows are the everyday tool for repeatable installations; policies, modules and agent versions are mostly set up by an Admin.

### Workflows

**Software → Workflows** is the catalog of distribution workflows, with the state of each computer from the last run: installed, already compliant, in progress, error.

- **Detection rules** say whether a computer is already compliant; then nothing runs.
- **Steps** (script, command, download, HTTP call, installation) run in order, each only if its conditions hold, for example membership of the user or computer in an Active Directory group.
- Every save creates a new **revision**; old ones stay readable.
- Run a workflow from the agent menu or a group, approved with MFA. Computers need the `workflow` module and AllowAdHocScripts not set to 0.

**Permanent assignment** (Admin): a workflow assigned to a group runs by itself on every member, including computers that join later, without a new MFA per computer. The Admin approves once the exact revision, how long the assignment lasts and the maximum time of each run. Suspending needs no MFA; once expired it must be approved again.

### Policies

**Deployment → Policy** tells agents what to collect or run periodically: inventory, update scans, vendor tools, reboots in a window. The standard collections run automatically without a policy. A policy is signed after an Admin approves it with MFA, once per version; agents receive it at the next connection and keep running it offline. Each rule chooses the action, the interval (1 minute to 7 days), clients/servers/platforms, an optional condition (e.g. a service exists) and an optional maintenance window. Scripts, shells and file sessions can never be in a policy.

### Modules

**Deployment → Modules** lists the signed modules that give agents their features. Modules shipped with the console are published here by an Admin with one approval; a new version must be published before it can be used.

### Agent versions and rings

**Deployment → Agent versions** shows the published releases. Computers in the **pilot** ring receive a new agent version first; **broad** receives it when the version is promoted. Set the ring of a computer from its panel or the bulk actions (Admin). An update that does not reconnect within 10 minutes is rolled back automatically.

## 8. Security dashboard and vulnerability management

The Security menu tells you which known vulnerabilities (CVEs) affect your computers, which are actively exploited, and opens the fix already prepared for the affected computers.

### Where the data comes from

The console compares the inventory of every computer with public sources, downloaded every 6 hours:

| Source | Used for |
| --- | --- |
| Microsoft security updates | CVEs fixed in each Windows build, compared with the computer's build |
| NVD (NIST) | CVEs and CVSS scores of known applications (browsers, Office tools, PDF readers...) |
| CISA KEV catalog | Which CVEs are actively exploited, and which are used in ransomware |
| Linux package managers | Security updates pending on Linux computers and the CVEs they fix |

Severity comes from the CVSS score: critical 9 or more, high from 7, medium from 4, low below 4; without a score the vendor's severity is used.

### The dashboard

**Security → Dashboard** shows five cards, each with its change over the chosen period (30, 90 days...), and two trend charts:

- **Cards**: vulnerabilities found, critical, high, actively exploited (CISA), affected computers. A click opens the list already filtered or sorted.
- **Vulnerabilities by severity**: distinct CVEs affecting at least one computer, day by day.
- **Exposures by severity**: CVE × computer pairs. This line goes down as updates reach the computers: it is the measure of your patching work.

Counts are recorded once a day, also when nobody opens the page, so the history builds up one day at a time. **Show as table** under each chart gives the numbers.

### Working the vulnerability list

1. Open **Security → Vulnerabilities**. Actively exploited CVEs are at the top.
2. Tick **only exploited** to see what to fix first; search by CVE, product, computer or KB; sort by severity or by number of computers.
3. Open a CVE: badges show *actively exploited (CISA KEV)*, *used in ransomware attacks*, CVSS and dates, with links to Microsoft and NVD.
4. The **Affected computers** table shows the installed version and the fix for each.
5. Click the prepared action and review it, then approve with MFA:
   - Windows: **Install security updates…** (security and critical classifications, so superseded KBs are not a problem);
   - applications: **Update the application with winget…**, or **Deploy … from the library…** when winget has no upgrade;
   - Linux: **Update the packages…**.
6. Check the job, then the CVE again after the next scan: the computer leaves the list once fixed.

### Special cases

- **User profile** badge: the application is installed in the user's profile. winget runs as the system account and cannot update it. Where safe, the console proposes installing the machine-wide version; for Firefox and Thunderbird ask the user to update from the application (a machine-wide copy would open an empty profile).
- **Ready, restart missing** badge: the fixed version is already downloaded; it is installed when the user closes and reopens the application.

### Recommended routine

- Daily: actively exploited CVEs and critical alerts.
- Weekly: critical and high CVEs, the Patch dashboard top 20, the Exposures trend.
- Monthly, after Patch Tuesday: Windows security updates on all clients, then servers in their window.

## 9. Alerts and checks

Alerts tell you when something needs attention; the red badge in the header counts the open ones.

### What raises an alert

| Event | Severity |
| --- | --- |
| A check starts failing (missing security updates older than 30 days, antivirus or firewall off, Trend Micro service down...) | From the check |
| RDP logon from an address outside the allowed subnets | Critical |
| Failed logons on 5 or more users from one source (password spraying) | Critical |
| 10 or more failed logons from one source | Warning |
| RDP from an allowed address never used before by that user on that computer (after 7 days of learning) | Warning |
| Account lockout | Warning |
| Trend Vision One Workbench alert on a matched computer | High/critical → critical, medium → warning |

### Handling alerts

1. Open **Reporting → Alerts**. Repeated alerts with the same cause are merged (count and last time).
2. Investigate from the agent page (Checks, Logons, Patches).
3. **Acknowledge** the alert when you have handled it. It reopens if the problem comes back.
4. Alerts raised by a check close by themselves when the check is no longer failing.

The subnets RDP is allowed from are set by an Admin in **Settings**; without them, private ranges are allowed.

## 10. Reports

**Reporting** answers "which computers have X?" from the latest inventory, and every table exports to CSV.

| Tab | What it shows |
| --- | --- |
| Dashboard | Approved agents, online now, pending approval, not seen for 7 days, with failing checks; manufacturers, models and OS at a glance. Filter by site or group. |
| Software inventory | Every application with versions, number of computers and users; system components optional. **Update this application…** opens the winget upgrade already prepared. |
| Computer inventory | Computers by installed software, OS, user, model or site; filters combine. Add extra columns from the inventory. |
| Operating systems | Computers by OS, version and build. |
| Logons | Local and remote desktop logons, most recent first, and failed attempts by source. |

### Advanced search

In **Computer inventory**, the advanced search combines any inventory field with AND, OR, NOT and parentheses. The page **fields and examples** lists every field. The simple fields below the bar are added to the search with AND: after **Search** they are written in the bar, where you can edit them.

| Syntax | Meaning | Example |
| --- | --- | --- |
| `field:value` | Contains (case-insensitive), `*` as wildcard | `hostname:VWUK*` |
| `field=value`, `!=` | Exact match / not equal | `bitlocker!=on` |
| `>` `<` | Numbers, versions, dates | `ram_gb<16`, `last_seen<30d`, `agent_version<1.1.3` |
| `software:"name@version"` | One application, optionally at a version | `software<"Google Chrome@142"` |

| Query | Finds |
| --- | --- |
| `os_family:client AND bitlocker!=on` | Clients with an unencrypted system disk |
| `secure_boot:no OR tpm:no` | Computers without Secure Boot or TPM |
| `software:"7-Zip" AND NOT software:"7-Zip@24*"` | 7-Zip installed but not version 24 |
| `free_pct<10 OR free_gb<5` | Low free space on the system disk |
| `battery<70` | Laptops with battery below 70% of original capacity |
| `uptime_days>30` | Computers not rebooted for over 30 days |
| `NOT software:"Trend Micro*"` | Computers without Trend Micro |

### Other sources of evidence

- **Security → Dashboard**: vulnerability trends (section 8), the best evidence of patching progress for management.
- **Patch**: compliance and the most outdated computers.
- **Reporting → Activity**: the audit log, for "who did what, when" (section 12).

## 11. Provisioning new computers

Provisioning prepares a freshly installed client in one go: an ordered list of workflows (software, antivirus, scripts) and reboots, started from the agent list.

> **Warning: freshly installed clients only.** The steps install, run scripts and reboot without notice to the user. Servers are refused, and you must confirm that the computers are new and their data may be lost.

### Profiles (Provisioning → Profiles)

- A profile is a list of up to 30 steps. Each step is a **workflow** (pinned to its revision at save time) or a **reboot**, and may be marked *continue on failure*.
- Every save creates a new **version**; versions never change afterwards.
- An **Admin approves a version once with MFA**, valid for 30 to 365 days. While it is valid, operators can run it with no further MFA, but nobody can change what its steps do.

### Starting a run

1. In **Agents**, tick the new, approved computers.
2. Choose **Start provisioning…** and pick the profile; the newest approved version is used.
3. Confirm the data-loss warning. One run at a time per computer.

### Following runs (Provisioning → Runs)

- Progress step by step, with the job of each step.
- The next step starts only when the agent has reported the previous one. After a reboot step the run resumes when the computer reconnects; if it is not back within 2 hours, the run fails.
- **Retry from the failed step** or **Cancel** (a step already sent still completes).

Coming next: start automatically at enrollment, offline domain join and ready-made Microsoft 365 Apps workflows.

## 12. Administration and audit

Admins configure the console; every change, like every operator action, lands in the tamper-evident Activity log.

### Activity (audit log)

**Reporting → Activity** records every operator action with author and time: approvals, commands with the full script text, shell sessions with every line typed, file transfers with path and SHA-256, settings changes, alerts acknowledged. Entries are hash-chained and cannot be changed or deleted from the console. Use it to answer "who did what, when".

### Setup (Admin)

**Setup** is a checklist computed from the console state, each item linked to where it is done: Entra ID sign-in with MFA, sites and subnets, RDP-allowed subnets, modules to publish, automatic collection, agent distribution, code signing, Active Directory.

### Settings (Admin)

- Sites and their subnets.
- Networks RDP is allowed from (outside them, RDP is a critical alert).
- File transfer limit per file (default 1 GB, at most 16 GB).
- Company logo.
- Policies (advanced).

### Active Directory comparison

When the `adinventory` module runs on a domain controller, the AD page lists **active computers without the agent** (usually the GPO did not apply), **stale computer objects** (no logon for over 90 days) and agents not found in the directory. The OU tree also appears in the agent list. The console holds no AD credentials.

### Linked consoles (federation)

On a customer console linked to a central console, a banner reminds you when you are operating through the central console. Every action is recorded at the customer under your name "via central console"; your MFA is still required and commands are still signed by the customer's own signer. The customer can cap the role of central operators, suspend or remove the link.

## 13. Troubleshooting and FAQ

| Symptom | Likely cause and what to do |
| --- | --- |
| A new PC does not appear | The agent has no console address or token: check the GPO or reinstall with the console's installer. The token may be expired, used up or revoked. |
| A PC is listed but receives nothing | It is still *pending*: approve it. |
| A job ends as *expired* | The computer was off for the whole validity window. Run it again with a longer validity (up to 48 h). |
| A job is *completed with errors* | The module ran but some items failed: open the job for the per-item result and log. |
| "Not allowed by local policy" | The computer's GPO forbids it (AllowAdHocScripts, AllowInteractiveShell, AllowRemoteControl). Ask the domain administrator. |
| Remote control shows nothing | No user is logged on or the screen is locked; the `screen` module must be published. |
| Windows updates never install | Look at the **Blockers** on the Patches tab; on a WSUS/Intune computer Tempra RMM only observes. Collect the logs from the Patches tab. |
| An outdated app is not updated by winget | It is installed in the user's profile (badge *user profile*): see section 8, Special cases. |
| The MFA window keeps asking | Sign in with the same account you use in the console, and complete MFA. |
| Vulnerability pages say data not yet downloaded | The console downloads the sources a few minutes after start, then every 6 hours. |
| Charts on the Security dashboard are almost empty | History is recorded one day at a time from the console update. |

### Good practice

- Approve only computers you recognize; revoke tokens that leak.
- Read the summary before approving with MFA: you are signing exactly that.
- Prefer groups and bulk actions over repeating the same command by hand.
- Close shell, remote control and file sessions when done.
- Use the pilot ring for new agent versions and test workflows on one computer first.
