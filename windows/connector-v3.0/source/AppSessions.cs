using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

public static class Store {
 public static readonly string Base=AppDomain.CurrentDomain.BaseDirectory;
 public static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 public static string Hash(string path){using(var f=File.OpenRead(path))using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
 public static void PrivateDir(string path){Directory.CreateDirectory(path);var a=new DirectorySecurity();a.SetAccessRuleProtection(true,false);foreach(var s in new[]{WindowsIdentity.GetCurrent().User,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null)})a.AddAccessRule(new FileSystemAccessRule(s,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.SetAccessControl(path,a);}
 public static void Verify(){foreach(var p in Payload.Hashes){string f=Path.Combine(Base,"engine",p.Key);if(!File.Exists(f)||Hash(f)!=p.Value)throw new Exception("底层组件缺失或校验不符："+p.Key+"。请重新解压完整包。");}}
 public static string Target(string path){
  if(String.IsNullOrWhiteSpace(path)||!Path.IsPathRooted(path)||path.StartsWith("\\\\")||path.IndexOfAny(new[]{'*','?',';','|',',','\r','\n','"'})>=0)throw new Exception("请选择一个本地 .exe 文件；不接受通配符、网络路径或多程序表达式。");
  string p=Path.GetFullPath(path);if(!p.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||!File.Exists(p))throw new Exception("找不到所选 .exe 文件。");
  if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new Exception("请选择真实 .exe 文件，不使用链接文件。");
  string name=Path.GetFileNameWithoutExtension(p).ToLowerInvariant();
  string[] denied={"flclash","clash","mihomo","gost","homerelay","netbridge","apponlyproxy","proxylane","proxybridge","sstap","cmd","powershell","pwsh","windowsterminal","explorer","conhost","svchost"};
  if(denied.Any(x=>name==x||(x.Length>=4&&name.StartsWith(x,StringComparison.Ordinal)))||p.IndexOf("\\FlClash\\",StringComparison.OrdinalIgnoreCase)>=0||p.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows)+"\\",StringComparison.OrdinalIgnoreCase))throw new Exception("为保护现有网络，不允许选择 FlClash、代理内核、连接器或系统命令解释器。");
  if(p.StartsWith(Base,StringComparison.OrdinalIgnoreCase)&&!name.StartsWith("proxyprobe",StringComparison.OrdinalIgnoreCase))throw new Exception("请选择你要使用的应用，而不是本工具组件。");
  if(Encoding.UTF8.GetByteCount(p)>800)throw new Exception("程序路径过长，请换用较短的真实路径。");return p;
 }
 public static string Quote(string value){var b=new StringBuilder("\"");int sl=0;foreach(char c in value){if(c=='\\'){sl++;continue;}if(c=='"'){b.Append('\\',sl*2+1);b.Append('"');sl=0;continue;}b.Append('\\',sl);sl=0;b.Append(c);}b.Append('\\',sl*2);return b.Append('"').ToString();}
 public static string Ini(string path,bool children,int port){return "[options]\r\nlanguage=zh-CN\r\nlastselected=AppOnly\r\nHookLanIP=0\r\nDisableLLMNR=0\r\nDisableMDNS=0\r\nDecryptHTTPS=0\r\nDecryptQUIC=0\r\n\r\n[proxy_AppOnly]\r\nType=SOCKS5\r\nHost=127.0.0.1\r\nPort="+port+"\r\nUser=\r\nPass=\r\nTransport=PLAIN\r\nPSK=\r\nHookTCP=1\r\nHookUDP=1\r\nBlockUDP=0\r\nBlockIPv6=1\r\ndnsOpt=1\r\nRedirectPrivateDNS=0\r\nRedirectDNS=\r\nHookChildProcess="+(children?"1":"0")+"\r\nChildFilterMode=1\r\nChildFilter="+path+"\r\nTargetFilterMode=0\r\nTargetFilter=\r\n";}
}

// The Job tracks only the engine and applications launched by this session.
// No KILL_ON_JOB_CLOSE: closing the launcher unexpectedly must not kill the user's work.
public sealed class Session : IDisposable {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {public uint cb;public string reserved,desktop,title;public uint x,y,cx,cy,cxChars,cyChars,fill,flags;public ushort show,cbReserved;public IntPtr reserved2,input,output,error;}
 [StructLayout(LayoutKind.Sequential)] struct PI {public IntPtr process,thread;public uint pid,tid;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder args,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref Startup si,out PI pi);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr a,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr j,int c,IntPtr data,uint n,out uint written);
 [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr p,uint code);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateHardLink(string path,string existing,IntPtr reserved);
 IntPtr job;Process engine;public string Runtime{get;private set;}public bool Ready{get;private set;}public int EnginePid{get{return engine==null?0:engine.Id;}}
 public bool EngineAlive{get{try{return engine!=null&&!engine.HasExited;}catch{return false;}}}
 public int ApplicationCount {get {if(job==IntPtr.Zero)return 0;const int size=32776;IntPtr p=Marshal.AllocHGlobal(size);try{uint done;if(!QueryInformationJobObject(job,3,p,size,out done))throw new Win32Exception(Marshal.GetLastWin32Error(),"无法核对本次程序生命周期");int count=Marshal.ReadInt32(p,4),n=0;if(count>4096)throw new Exception("本次程序子进程过多");for(int i=0;i<count;i++)if(Marshal.ReadIntPtr(p,8+i*IntPtr.Size).ToInt64()!=EnginePid)n++;return n;}finally{Marshal.FreeHGlobal(p);}}}
 public void Start(string selected,string args,bool children,int port=11081){
  if(engine!=null)throw new Exception("请先结束上一个会话");string target=Store.Target(selected);if(args.IndexOfAny(new[]{'\r','\n','\0'})>=0)throw new Exception("启动参数不能包含换行");
  foreach(var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(target)))using(p){try{if(String.Equals(Path.GetFullPath(p.MainModule.FileName),target,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("请先正常退出目标程序及其后台实例，再从本工具启动，避免复用未代理的旧进程。");}catch(Win32Exception){throw new InvalidOperationException("目标程序可能已在后台运行或权限不同，请先正常退出后重试。");}}
  string appName=Path.GetFileNameWithoutExtension(target).ToLowerInvariant();
  if(new[]{"chrome","msedge","brave","chromium","vivaldi","opera","360chrome"}.Contains(appName)){
   if(args.IndexOf("--proxy-server",StringComparison.OrdinalIgnoreCase)>=0||args.IndexOf("--proxy-pac-url",StringComparison.OrdinalIgnoreCase)>=0)throw new Exception("启动参数已指定其他代理，请移除此程序的 --proxy-server / --proxy-pac-url 参数。");
   args+=" --no-proxy-server"; // Per-launch only; never modifies the Windows/FlClash proxy.
  }
  Store.Verify();ProxyProbe.Greeting(port);
  string parent=Path.Combine(Store.Base,"sessions");Store.PrivateDir(parent);Runtime=Path.Combine(parent,"run-"+Guid.NewGuid().ToString("N"));Store.PrivateDir(Runtime);
  foreach(var file in Payload.Hashes.Keys){string to=Path.Combine(Runtime,file),from=Path.Combine(Store.Base,"engine",file);if(!CreateHardLink(to,from,IntPtr.Zero))File.Copy(from,to);}
  File.WriteAllText(Path.Combine(Runtime,"ProxyLane.ini"),Store.Ini(target,children,port),Encoding.Unicode);
  string eventName="Local\\AppOnlyProxy-Ready-"+Guid.NewGuid().ToString("N");
  using(var ready=new EventWaitHandle(false,EventResetMode.ManualReset,eventName)){
   string exe=Path.Combine(Runtime,"ProxyLane64.exe");string command=Store.Quote(exe)+" --auto --profile AppOnly --run "+Store.Quote(target)+" --bootstrap-event "+Store.Quote(eventName)+(String.IsNullOrWhiteSpace(args)?"":" -- "+args);
   job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
   var si=new Startup();si.cb=(uint)Marshal.SizeOf(typeof(Startup));si.flags=1;si.show=0;PI pi;
   var env=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);foreach(System.Collections.DictionaryEntry v in Environment.GetEnvironmentVariables())env[(string)v.Key]=(string)v.Value;
   foreach(string key in new[]{"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"})env.Remove(key);env["NO_PROXY"]="*";
   string block=String.Join("\0",env.Select(k=>k.Key+"="+k.Value).ToArray())+"\0\0";IntPtr memory=Marshal.StringToHGlobalUni(block);
   try{if(!CreateProcess(exe,new StringBuilder(command),IntPtr.Zero,IntPtr.Zero,false,0x08000404,memory,Path.GetDirectoryName(target),ref si,out pi))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{Marshal.FreeHGlobal(memory);}
   try{if(!AssignProcessToJobObject(job,pi.process)){TerminateProcess(pi.process,1);throw new Win32Exception(Marshal.GetLastWin32Error(),"不能隔离本次会话，未启动目标程序");}engine=Process.GetProcessById((int)pi.pid);if(ResumeThread(pi.thread)==0xFFFFFFFF){TerminateProcess(pi.process,1);throw new Win32Exception(Marshal.GetLastWin32Error());}}finally{CloseHandle(pi.thread);CloseHandle(pi.process);}
   for(int k=0;k<200;k++){if(ready.WaitOne(100)){Ready=true;return;}if(engine.HasExited)throw new Exception("底层启动失败（代码 "+engine.ExitCode+"）。代码 7 常表示该程序不接受进程代理；未继续无代理启动。");}
   throw new Exception("等待目标程序启动确认超时。若目标程序已有后台实例，请先正常退出后重试。");
  }
 }
 public bool StopIfIdle(){if(ApplicationCount>0)return false;if(engine!=null){if(!engine.HasExited){engine.Kill();engine.WaitForExit(5000);}engine.Dispose();engine=null;}Ready=false;if(job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}Clean();return true;}
 void Clean(){if(Runtime==null)return;try{string parent=Path.GetFullPath(Path.Combine(Store.Base,"sessions"))+Path.DirectorySeparatorChar;string run=Path.GetFullPath(Runtime);if(!run.StartsWith(parent,StringComparison.OrdinalIgnoreCase)||!Path.GetFileName(run).StartsWith("run-",StringComparison.Ordinal))return;foreach(string f in Payload.Hashes.Keys.Concat(new[]{"ProxyLane.ini","ProxyLane64.ini"})){string p=Path.Combine(run,f);if(File.Exists(p))File.Delete(p);}if(!Directory.EnumerateFileSystemEntries(run).Any())Directory.Delete(run);}catch{}Runtime=null;}
 public void Dispose(){try{if(!StopIfIdle()&&job!=IntPtr.Zero){CloseHandle(job);job=IntPtr.Zero;}}catch{} }
}

