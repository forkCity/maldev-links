# redteam/maldev links
Massive thanks to @janoglezcampos for fixing my trash formatting and categorizing it. Now it wont give you eye cancer.
I sometimes put stuff on [my blog](https://codex-7.gitbook.io/). Existing research I read and find useful will be put here.

## Hooking/unhooking
* [Lets Create An EDR… And Bypass It! Part 1: How EDRs inject DLLs to hook processes](https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/)
* [Lets Create An EDR… And Bypass It! Part 2: Preventing the hook from loading into our process by preventing the DLL load](https://ethicalchaos.dev/2020/06/14/lets-create-an-edr-and-bypass-it-part-2/)
* [Userland DLL hooks C# code sample - SharpUnhooker](https://github.com/GetRektBoy724/SharpUnhooker)
* [Evading userland DLL hooks in C# using D/Invoke - D-Pwn](https://github.com/FatCyclone/D-Pwn)
* [Adventures in Dynamic Evasion; unhooking](https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa)
* [Kernel callbacks](http://www.nynaeve.net/?p=200)
* [Process instrumentation callbacks](https://winternl.com/detecting-manual-syscalls-from-user-mode/)
* [Hooking via exceptions](https://medium.com/@fsx30/vectored-exception-handling-hooking-via-forced-exception-f888754549c6)
* [Evading EDR Detection with Reentrancy Abuse](https://www.deepinstinct.com/blog/evading-antivirus-detection-with-inline-hooks)
* [Unhooking Sentinel1](https://twitter.com/ninjaparanoid/status/1493396083644399616?s=21)
* [Emulating Covert Operations - Dynamic Invocation (Avoiding PInvoke & API Hooks)](https://thewover.github.io/Dynamic-Invoke/)
* [Halo's Gate: Dynamically resolving syscalls based on unhooked syscalls](https://blog.sektor7.net/#!res/2021/halosgate.md)
* [Shellcode detection using realtime kernel monitoring](https://www.countercraftsec.com/blog/post/shellcode-detection-using-realtime-kernel-monitoring/)
* [EDR tampering](https://www.infosec.tirol/how-to-tamper-the-edr/)

# AMSI/ETW/ETW-TI
* [Proxying DLL Loads for hiding ETW-TI call stack tracing](https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/)
* [Evading ETW-TI call stack tracing using custom call stacks](https://0xdarkvortex.dev/hiding-in-plainsight/)
* [Attacks on ETW Blind EDR Sensors](https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf)
* [Detecting Adversarial Tradecrafts Tools by leveraging ETW](https://github.com/RedTeamOperations/Detecting-Adversarial-Tradecrafts-Tools-by-leveraging-ETW)
* [Data Only Attack: Neutralizing EtwTi Provider](https://public.cnotools.studio/bring-your-own-vulnerable-kernel-driver-byovkd/exploits/data-only-attack-neutralizing-etwti-provider)

# Sleep obfuscation/masking
* [Stack Spoofing](https://github.com/countercept/CallStackSpoofer)
* [SleepyCrypt: Encrypting a running  PE  image while it sleeps](https://www.solomonsklash.io/SleepyCrypt-shellcode-to-encrypt-a-running-image.html)
* [Sleeping with a Mask On (Cobalt Strike)](https://adamsvoboda.net/sleeping-with-a-mask-on-cobaltstrike/)
* [GPUSleep](https://github.com/oXis/GPUSleep)
* [SilentMoonWalk - a thread stack spoofer](https://github.com/klezVirus/SilentMoonwalk)
* [CallStackMasker](https://github.com/Cobalt-Strike/CallStackMasker)

# Rootkits
* [Bootlicker - UEFI rootkit](https://github.com/realoriginal/bootlicker)
* [Niddhogg - kernel driver rootkit](https://github.com/Idov31/Nidhogg)
  
# VBA
* [VBA: resolving exports in runtime without NtQueryInformationProcess or GetProcAddress](https://adepts.of0x.cc/vba-exports-runtime/)
# Direct syscalls
* [SysWhispers is dead, long live SysWhispers!](https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)
* [Combining Direct System Calls and sRDI to bypass AV/EDR](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
* [Implementing Syscalls in Cobalt Strike Part 1 - Battling Imports and Dependencies](https://blog.xenoscr.net/2022/03/12/Implementing-Syscalls-in-Cobalt-Strike-Part-1-Battling-Imports-and-Dependencies.html)
* [When You sysWhisper Loud Enough for AV to Hear You](https://captmeelo.com//redteam/maldev/2021/11/18/av-evasion-syswhisper.html)


# Process injection
* [Process injection sample codes](https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop)
* [KnownDLLs injection](https://www.codeproject.com/Articles/325603/Injection-into-a-Process-Using-KnownDlls)
* [Abusing Windows’ Implementation of Fork() for Stealthy Memory Operations](https://billdemirkapi.me/abusing-windows-implementation-of-fork-for-stealthy-memory-operations/)
* [Object Overloading](https://www.trustedsec.com/blog/object-overloading/)
* [HintInject](https://github.com/frkngksl/HintInject)
* [APC techniques](https://github.com/repnz/apc-research)
* [Unicode Reflection - Event Null Byte Injection](https://www.hawk.io/blog/unicode-reflection-event-null-byte-injection)
* [Alternative Process Injection](https://www.netero1010-securitylab.com/evasion/alternative-process-injection)
* [Weaponizing mapping injection](https://splintercod3.blogspot.com/p/weaponizing-mapping-injection-with.html)
* [Advanced-Process-Injection-Workshop by CyberWarFare Labs](https://github.com/RedTeamOperations/Advanced-Process-Injection-Workshop)
* [Threadless inject](https://github.com/CCob/ThreadlessInject)
* [Function hijacking](https://klezvirus.github.io/RedTeaming/AV_Evasion/FromInjectionToHijacking/)



## General evasion/Execution techs

* [Operational challenges in offensive C - SpectreOps](https://posts.specterops.io/operational-challenges-in-offensive-c-355bd232a200)
* [WORKSHOP // A journey into malicious code tradecraft for Windows // Silvio La Porta and Antonio Villani](https://vimeo.com/727453909) 
* [Python library for ML evasion and detection etc](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
* [Massive guide on bypassing anticheat and antidebug - also works in malware against EDRs](https://guidedhacking.com/forums/anticheat-bypass-antidebug-tutorials.46/)
* [3in1: Project aimed to Bypass Some Av Products, Using Different, Advanced Features](https://gitlab.com/ORCA666/3in1)
* [Evasion-Practice: Different evasion techniques/PoCs](https://github.com/cinzinga/Evasion-Practice)
* [Reading and writing remote process data without using ReadProcessMemory / WriteProcessMemory](https://www.x86matthew.com/view_post?id=read_write_proc_memory)
* [SharpEDRChecker: EDR detection](https://redteaming.co.uk/2021/03/18/sharpedrchecker/)
* [StackScraper - Capturing sensitive data using real-time stack scanning against a remote process](https://www.x86matthew.com/view_post?id=stack_scraper)
* [WindowsNoExec - Abusing existing instructions to executing arbitrary code without allocating executable memory](https://www.x86matthew.com/view_post?id=windows_no_exec)
* [Masking Malicious Memory Artifacts – Part III: Bypassing Defensive Scanners](https://www.forrest-orr.net/post/masking-malicious-memory-artifacts-part-iii-bypassing-defensive-scanners)
* [EDR and Blending In: How Attackers Avoid Getting Caught: Part 2](https://www.optiv.com/insights/source-zero/blog/edr-and-blending-how-attackers-avoid-getting-caught)
* [Adventures in Dynamic Evasion](https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa)
* [Hindering Threat Hunting, a tale of evasion in a restricted environment](https://www.tarlogic.com/blog/hindering-threat-hunting-a-tale-of-evasion-in-a-restricted-environment/)
* [One thousand and one ways to copy your shellcode to memory (VBA Macros)](https://adepts.of0x.cc/alternatives-copy-shellcode/)
* [Delete-self-poc: A way to delete a locked, or current running executable, on disk](https://github.com/LloydLabs/delete-self-poc)
* [Writing Beacon Object Files: Flexible, Stealthy, and Compatible: Direct syscalls from the real ntdll to bypas syscall detection](https://www.cobaltstrike.com/blog/writing-beacon-object-files-flexible-stealthy-and-compatible/)
* [Kernel Karnage – Part 9 (Finishing Touches)](https://blog.nviso.eu/2022/02/22/kernel-karnage-part-9-finishing-touches/)
* [Using the kernel callback table to execute code](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)
* [Invisible Sandbox Evasion](https://research.checkpoint.com/2022/invisible-cuckoo-cape-sandbox-evasion/)
* [Important: Reduce ur entropy](https://twitter.com/hardwaterhacker/status/1502425183331799043?s=21)
* [compile your code into mov instructions](https://github.com/xoreaxeaxeax/movfuscator)



## Operational stuff - OPSEC, TTPs, etc.
* [Life of a payload](https://attl4s.github.io/assets/pdf/Understanding_a_Payloads_Life.pdf)
* [PPLMedic](https://github.com/itm4n/PPLmedic)
* [Parent-child process strcuture](https://mrd0x.com/introduction-to-parent-child-process-evasion/)
* [Echotrail - windows process stats](https://https://www.echotrail.io/)
* [Browser In The Browser (BITB) Attack](https://mrd0x.com/browser-in-the-browser-phishing-attack/)
* [Black Hills Infosec - Coercion and relays](https://www.youtube.com/watch?v=b0lLxLJKaRs)
* [Pocket Guide to OPSEC in Adversary Emulation](https://ristbs.github.io/2023/02/08/your-pocket-guide-to-opsec-in-adversary-emulation.html)



## C2 related:

* [Counter Strike 1.6 as Malware C2](https://www.youtube.com/watch?v=b2L1lWtwBiI&t=1s)
* [OffensiveNotion](https://github.com/mttaggart/OffensiveNotion)
* [We Put A C2 In Your Notetaking App: OffensiveNotion](https://medium.com/@huskyhacks.mk/we-put-a-c2-in-your-notetaking-app-offensivenotion-3e933bace332)
* [Building C2 implants in C++](https://shogunlab.gitbook.io/building-c2-implants-in-cpp-a-primer/)
* [C2 matrix - all your c2 needs here](https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc/edit#gid=0)



