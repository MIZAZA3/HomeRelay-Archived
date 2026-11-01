using System;using System.Diagnostics;using System.IO;using System.Linq;using System.Net;using System.Net.NetworkInformation;using System.Runtime.InteropServices;using System.Text;using System.Threading;
static class GlobalHelper{
 delegate bool Ctrl(uint signal);static Ctrl ignore=signal=>true;[DllImport("kernel32.dll")]static extern bool SetConsoleCtrlHandler(Ctrl h,bool add);[DllImport("kernel32.dll")]static extern bool GenerateConsoleCtrlEvent(uint signal,uint group);
 static string directory;static void Status(string s){try{File.WriteAllText(Path.Combine(directory,"status.txt"),s,new UTF8Encoding(false));}catch{}}
 static int Main(string[] a){Process engine=null;try{if(a.Length!=5||a[0]!="--run")return 1;int pid=int.Parse(a[1]),port=int.Parse(a[3]);long ticks=long.Parse(a[2]);string id=a[4];if(!System.Text.RegularExpressions.Regex.IsMatch(id,"^[a-f0-9]{32}$")||port<1024||port>65532)return 1;
  directory=Path.Combine(Common.Base,"global","run-"+id);if(!Directory.Exists(directory)||(File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0)return 1;
  using(var parent=Process.GetProcessById(pid)){if(parent.StartTime.ToUniversalTime().Ticks!=ticks||!String.Equals(parent.MainModule.FileName,Path.Combine(Common.Base,"HomeRelayConnector.exe"),StringComparison.OrdinalIgnoreCase))throw new Exception("启动者身份不符");
   var conflicts=GlobalSupport.Conflicts();if(conflicts.Count>0)throw new Exception("检测到网络冲突，未更改网络："+String.Join("；",conflicts));GlobalSupport.Verify();
   using(var locked=File.Open(GlobalSupport.Engine,FileMode.Open,FileAccess.Read,FileShare.Read))using(var stop=EventWaitHandle.OpenExisting("Local\\HomeRelayV3-Global-"+id)){
    using(var sha=System.Security.Cryptography.SHA256.Create())if(BitConverter.ToString(sha.ComputeHash(locked)).Replace("-","").ToLowerInvariant()!=GlobalSupport.EngineHash)throw new Exception("全局内核锁定校验失败");
    string config=Path.Combine(directory,"global.json");File.WriteAllText(config,Common.Json.Serialize(GlobalSupport.Config(port,"HR3-"+id.Substring(0,8),true)),new UTF8Encoding(false));SetConsoleCtrlHandler(ignore,true);
    engine=new Process{StartInfo=new ProcessStartInfo(GlobalSupport.Engine,"run -c "+Common.Q(config)){WorkingDirectory=Path.GetDirectoryName(GlobalSupport.Engine),UseShellExecute=false,CreateNoWindow=false,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true}};
    engine.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)try{File.AppendAllText(Path.Combine(directory,"engine.log"),e.Data+Environment.NewLine);}catch{}};engine.OutputDataReceived+=(s,e)=>{};engine.Start();engine.BeginErrorReadLine();engine.BeginOutputReadLine();
    bool ready=false;int missing=0;
    while(!stop.WaitOne(500)&&!parent.HasExited&&!engine.HasExited){bool adapter=NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="HR3-"+id.Substring(0,8)&&n.OperationalStatus==OperationalStatus.Up);if(adapter&&!ready){ready=true;Status("RUNNING · 全局 TCP/UDP；IPv6公网阻断防旁路，局域网直连");}
     bool proxy=IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(p=>p.Port==port&&p.Address.Equals(IPAddress.Loopback));missing=proxy?0:missing+1;if(missing>=6)break;
    }
    Status("STOPPING · 正在回收专用 TUN 和路由");if(!engine.HasExited){GenerateConsoleCtrlEvent(1,0);if(!engine.WaitForExit(12000)){engine.Kill();engine.WaitForExit(3000);Status("STOPPED · 内核已退出，请核对网络状态");return 2;}}Status("STOPPED · 全局模式已关闭");
   }
  }return 0;
 }catch(Exception e){Status("ERROR · "+e.Message);return 1;}finally{if(engine!=null){try{if(!engine.HasExited){GenerateConsoleCtrlEvent(1,0);if(!engine.WaitForExit(5000))engine.Kill();}}catch{}engine.Dispose();}}}
}
