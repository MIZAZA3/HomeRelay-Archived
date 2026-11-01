using System;using System.Collections.Generic;using System.Diagnostics;using System.Drawing;using System.IO;using System.Linq;using System.Net;using System.Net.NetworkInformation;using System.Net.Security;using System.Net.Sockets;using System.Security.Cryptography;using System.Text;using System.Threading;using System.Threading.Tasks;using System.Web.Script.Serialization;using System.Windows.Forms;

public class DeviceIdentity {public string Id,Secret,PublicKey,PrivateKey;}
public sealed class AgentCore : IDisposable {
 public string State="stopped",NodeId="",Label="",SourceIPv4="",InterfaceName="",Runtime;public int HomePort;public bool TunnelReady;public Action<string> Log;
 volatile bool stopped;Task loop;Common.Job job;readonly List<Process> children=new List<Process>();DeviceIdentity identity;Common.Adapter adapter;
 string ssh{get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","OpenSSH","ssh.exe");}}
 public AgentCore(Action<string> log){Log=log;}
 DeviceIdentity Identity(){string p=Path.Combine(Common.Base,"identity");Common.PrivateDir(p);string file=Path.Combine(p,"device.dpapi");if(File.Exists(file))return Common.Json.Deserialize<DeviceIdentity>(Common.Unprotect(File.ReadAllBytes(file),"HomeRelayAgent-v2"));
  string generator=Path.Combine(Path.GetDirectoryName(ssh),"ssh-keygen.exe");if(!File.Exists(generator))throw new Exception("未找到 Windows OpenSSH 客户端，请在可选功能安装 OpenSSH 客户端。");
  string key=Path.Combine(p,"new-device-key");if(File.Exists(key)||File.Exists(key+".pub"))throw new Exception("上次身份生成未完成，请保留 identity 文件夹后联系管理员。");
  using(var proc=Process.Start(new ProcessStartInfo(generator,"-q -t ed25519 -N \"\" -C HomeRelayV2-agent -f "+Common.Q(key)){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true})){if(!proc.WaitForExit(20000)){proc.Kill();throw new Exception("生成转发身份超时");}if(proc.ExitCode!=0)throw new Exception("未能生成独立转发身份，未使用任何已有 SSH 私钥。");}
  var pub=File.ReadAllText(key+".pub").Split(new[]{' ','\r','\n'},StringSplitOptions.RemoveEmptyEntries);var d=new DeviceIdentity{Id=Guid.NewGuid().ToString("N"),Secret=Common.Random(),PublicKey=pub[0]+" "+pub[1],PrivateKey=File.ReadAllText(key)};File.WriteAllBytes(file,Common.Protect(Common.Json.Serialize(d),"HomeRelayAgent-v2"));File.Delete(key);File.Delete(key+".pub");return d;
 }
 public void Start(){if(loop!=null&&!loop.IsCompleted)throw new Exception("已在运行");stopped=false;loop=Task.Run(()=>Run());}
 void Run(){try{Common.Verify();identity=Identity();NodeId=identity.Id;bool registered=false;string old="";int failures=0;
  while(!stopped){try{var data=Common.D("id",identity.Id,"secret",identity.Secret,"version","2.0","tunnel_ready",TunnelReady);if(!registered)data["pubkey"]=identity.PublicKey;
    Dictionary<string,object> result=null;Exception last=null;
    foreach(var a in Common.Adapters()){if(stopped)break;try{result=Common.Post(Bootstrap.Server,Bootstrap.Domain,"/__home_relay_v2/"+(registered?"poll":"register"),data,a,Bootstrap.Enrollment);adapter=a;break;}catch(Exception e){last=e;}}
    if(stopped)break;if(result==null)throw last??new Exception("未找到可用的物理网络");registered=true;failures=0;SourceIPv4=adapter.Address;InterfaceName=adapter.Name;State=(string)result["state"];Label=(string)result["label"];
    if(State!=old){Log(State=="pending"?"已连接服务器，等待管理员启用；当前不承接任何流量。":State=="enabled"?"管理员已启用本节点，正在准备转发通道。":State=="idle"?"管理员设置为闲置：保持在线，不接新流量。":"管理员已拒绝或停用本节点。");old=State;}
    if(State=="enabled"||State=="idle"){
     if(job!=null&&children.Any(p=>p.HasExited)){StopTunnel();Log("转发进程中断，正在自动重连。");}
     if(job==null&&!stopped)StartTunnel(Convert.ToInt32(result["remote_port"]),(string)result["home_password"]);
    }else StopTunnel();
   }catch(Exception e){failures++;State="reconnecting";if(failures==1||failures%6==0)Log("连接暂不可用，将自动重试："+e.Message);if(failures>=3)StopTunnel();}
   for(int i=0;i<100&&!stopped;i++)Thread.Sleep(100);
  }
 }catch(Exception e){State="error";Log("启动未完成："+e.Message);}finally{StopTunnel();if(stopped)State="stopped";}}
 void Launch(string exe,string args,string tag){if(stopped)throw new OperationCanceledException();var p=new Process{StartInfo=new ProcessStartInfo(exe,args){WorkingDirectory=Runtime,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}};p.ErrorDataReceived+=(s,e)=>{if(e.Data==null)return;if(tag=="SSH"&&e.Data.Contains("remote forward success")){TunnelReady=true;Log("加密转发通道已建立；管理员可在面板检测 TCP / UDP。");}if(!e.Data.StartsWith("debug")&&!e.Data.StartsWith("Authenticated")&&!e.Data.StartsWith("OpenSSH_")&&!e.Data.Contains("home_password"))Log(tag+"："+e.Data.Replace(identity.Secret,"[隐藏]"));};p.OutputDataReceived+=(s,e)=>{};p.Start();job.Add(p);children.Add(p);p.BeginErrorReadLine();p.BeginOutputReadLine();}
 void StartTunnel(int remote,string password){if(remote<22000||remote>=22032)throw new Exception("服务器返回端口越界");if(stopped)return;
  string parent=Path.Combine(Common.Base,"runtime");Common.PrivateDir(parent);Runtime=Path.Combine(parent,"run-"+Guid.NewGuid().ToString("N"));Common.PrivateDir(Runtime);HomePort=Common.FreePort();job=new Common.Job();
  File.WriteAllText(Path.Combine(Runtime,"device_key"),identity.PrivateKey.Replace("\r\n","\n"),new UTF8Encoding(false));File.WriteAllText(Path.Combine(Runtime,"known_hosts"),Bootstrap.KnownHosts,new UTF8Encoding(false));
  var home=Common.D("services",new[]{Common.D("name","home","addr","127.0.0.1:"+HomePort,"handler",Common.D("type","socks5","auth",Common.D("username","home","password",password),"metadata",Common.D("udp",true,"notls",true,"bind",false,"udpBufferSize",65535)),"listener",Common.D("type","tcp"),"resolver","public-dns","bypasses",new[]{"deny-private"},"metadata",Common.D("interface",adapter.Name))},"resolvers",new[]{Common.D("name","public-dns","nameservers",new[]{Common.D("addr","223.5.5.5:53","only","ipv4"),Common.D("addr","119.29.29.29:53","only","ipv4")})},"bypasses",new[]{Common.D("name","deny-private","matchers",Common.Deny)},"log",Common.D("level","warn","output","stderr","format","json"));
  File.WriteAllText(Path.Combine(Runtime,"home.json"),Common.Json.Serialize(home),new UTF8Encoding(false));Launch(Path.Combine(Common.Base,"gost.exe"),"-C "+Common.Q(Path.Combine(Runtime,"home.json")),"出口");
  for(int i=0;i<50&&!stopped;i++){if(IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Any(p=>p.Port==HomePort&&p.Address.Equals(IPAddress.Loopback)))break;Thread.Sleep(100);}
  if(stopped){StopTunnel();return;}
  string cfg="Host relay\n HostName "+Bootstrap.Server+"\n Port 22\n User gost-home-auto\n IdentityFile "+Common.Q(Path.Combine(Runtime,"device_key"))+"\n UserKnownHostsFile "+Common.Q(Path.Combine(Runtime,"known_hosts").Replace('\\','/'))+"\n IdentitiesOnly yes\n StrictHostKeyChecking yes\n BatchMode yes\n ForwardAgent no\n ConnectTimeout 15\n ServerAliveInterval 15\n ServerAliveCountMax 2\n ExitOnForwardFailure yes\n ProxyCommand "+Common.Q(Path.Combine(Common.Base,"NetBridge.exe").Replace('\\','/'))+" "+adapter.Index+" "+adapter.Address+" %h %p\n";
  File.WriteAllText(Path.Combine(Runtime,"ssh_config"),cfg,new UTF8Encoding(false));Launch(ssh,"-v -F "+Common.Q(Path.Combine(Runtime,"ssh_config"))+" -N -T -R 127.0.0.1:"+remote+":127.0.0.1:"+HomePort+" relay","SSH");
 }
 void StopTunnel(){TunnelReady=false;if(job!=null){job.Dispose();job=null;}foreach(var p in children)try{if(!p.HasExited)p.Kill();p.WaitForExit(1000);p.Dispose();}catch{}children.Clear();if(Runtime!=null){Common.Clean(Runtime,Path.Combine(Common.Base,"runtime"));Runtime=null;}}
 public void Dispose(){stopped=true;try{if(loop!=null)loop.Wait(1000);}catch{}if(loop==null||loop.IsCompleted)StopTunnel();}
}

sealed class AgentForm:Form{
 AgentCore core;Button start,stop;Label state,identity;TextBox log;System.Windows.Forms.Timer timer;
 public AgentForm(){Text="家宽出口端 · 自动报到 2.0";Font=new Font("Microsoft YaHei UI",10);ClientSize=new Size(800,560);MinimumSize=new Size(770,580);StartPosition=FormStartPosition.CenterScreen;BackColor=Color.FromArgb(244,247,251);AutoScaleMode=AutoScaleMode.Dpi;
  Controls.Add(new Label{Text="点一下，让管理面板发现这台电脑",Location=new Point(28,25),AutoSize=true,Font=new Font(Font.FontFamily,21,FontStyle.Bold),ForeColor=Color.FromArgb(25,42,67)});
  Controls.Add(new Label{Text="自动登记独立身份 · 管理员决定启用 / 闲置 · 不修改 FlClash 或系统网络",Location=new Point(30,80),AutoSize=true,ForeColor=Color.DimGray});
  state=new Label{Text="● 已停止",Location=new Point(30,125),AutoSize=true,Font=new Font(Font.FontFamily,14,FontStyle.Bold),ForeColor=Color.Gray};Controls.Add(state);identity=new Label{Text="首次启动会在本机生成独立身份，不需要填写服务器账号。",Location=new Point(30,173),Size=new Size(740,60)};Controls.Add(identity);
  start=new Button{Text="启动转发",Location=new Point(30,246),Size=new Size(170,45)};stop=new Button{Text="停止",Location=new Point(217,246),Size=new Size(115,45),Enabled=false};Controls.Add(start);Controls.Add(stop);
  Controls.Add(new Label{Text="转发记录（不显示凭据，不记录网页内容）",Location=new Point(30,320),AutoSize=true,ForeColor=Color.DimGray});log=new TextBox{Location=new Point(30,351),Size=new Size(740,156),Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,BackColor=Color.White,Anchor=AnchorStyles.Top|AnchorStyles.Left|AnchorStyles.Right|AnchorStyles.Bottom};Controls.Add(log);
  var footer=new Label{Text="新节点默认待启用。关闭本工具只停止本次转发，不关闭其他程序。",Location=new Point(30,529),AutoSize=true,ForeColor=Color.DimGray,Anchor=AnchorStyles.Bottom|AnchorStyles.Left};Controls.Add(footer);
  start.Click+=(s,e)=>{if(core!=null)return;core=new AgentCore(Log);core.Start();start.Enabled=false;stop.Enabled=true;};stop.Click+=(s,e)=>{if(core!=null)core.Dispose();core=null;start.Enabled=true;stop.Enabled=false;state.Text="● 已停止";state.ForeColor=Color.Gray;};
  timer=new System.Windows.Forms.Timer{Interval=500};timer.Tick+=(s,e)=>{if(core==null)return;var names=new Dictionary<string,string>{{"pending","已连接，等待管理员启用"},{"enabled",core.TunnelReady?"已启用 · 转发通道已就绪":"已启用，正在建立转发通道"},{"idle","在线闲置，不接新流量"},{"rejected","已被管理员停用"},{"reconnecting","正在连接 / 自动重连"},{"stopped","已停止"},{"error","启动未完成"}};state.Text="● "+(names.ContainsKey(core.State)?names[core.State]:"正在生成身份 / 连接服务器");state.ForeColor=core.State=="enabled"&&core.TunnelReady?Color.ForestGreen:core.State=="error"?Color.Firebrick:Color.DarkOrange;identity.Text=String.IsNullOrEmpty(core.NodeId)?"正在准备独立身份…":"节点编号："+core.NodeId+"\n网络："+core.InterfaceName+" / "+core.SourceIPv4;};timer.Start();FormClosing+=(s,e)=>{timer.Stop();if(core!=null)core.Dispose();};
 }
 void Log(string s){if(IsDisposed)return;if(InvokeRequired){try{BeginInvoke(new Action<string>(Log),s);}catch{}return;}if(log.TextLength>24000)log.Text=log.Text.Substring(log.TextLength-12000);log.AppendText(DateTime.Now.ToString("HH:mm:ss")+"  "+s+Environment.NewLine);}
}
static class AgentProgram{
 [STAThread]static int Main(string[] a){try{if(a.Length==2&&a[0]=="--headless"){string p=a[1];using(var c=new AgentCore(s=>{try{File.AppendAllText(p+".log",DateTime.Now.ToString("o")+" "+s+Environment.NewLine);}catch{}})){c.Start();for(int i=0;i<7200&&!File.Exists(p+".stop");i++){File.WriteAllText(p,Common.Json.Serialize(Common.D("state",c.State,"id",c.NodeId,"ready",c.TunnelReady,"home_port",c.HomePort)));Thread.Sleep(500);}}return 0;}
  bool fresh;using(var m=new Mutex(true,"Local\\HomeRelayAutoAgent-v2",out fresh)){if(!fresh){MessageBox.Show("出口端已运行，请使用已有窗口。");return 1;}Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new AgentForm());}return 0;
 }catch(Exception x){MessageBox.Show(x.Message,"出口端");return 1;}}
}
