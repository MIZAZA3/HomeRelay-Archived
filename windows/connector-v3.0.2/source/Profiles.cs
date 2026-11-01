using System;using System.Collections.Generic;using System.IO;using System.Linq;using System.Net;using System.Net.Security;using System.Net.Sockets;using System.Security;using System.Text;
public static class Profiles{
 public static void Validate(NodeConfig c){if(c==null)throw new Exception("连接卡为空");if(c.Version==2){ConnectorCore.Validate(c);return;}if(c.Version!=3||c.Server!="203.0.113.20"||!c.RequiresPassword||!System.Text.RegularExpressions.Regex.IsMatch(c.NodeId??"","^[a-f0-9]{32}$"))throw new Exception("不是有效的新版连接卡");if((c.Label??"").Length>128)throw new Exception("节点备注过长");}
 public static NodeConfig Resolve(NodeConfig card,string password){Validate(card);if(card.Version==2)return card;if(password==null||password.Length<8||password.Length>128)throw new Exception("请输入该节点的使用密码（8–128个字符）");Exception last=null;
  foreach(var a in Common.Adapters())try{return Unlock(card,password,a);}catch(SecurityException){throw;}catch(Exception e){last=e;}
  throw last??new Exception("未找到可用物理网络");
 }
 static NodeConfig Unlock(NodeConfig card,string password,Common.Adapter a){byte[] body=Encoding.UTF8.GetBytes(Common.Json.Serialize(Common.D("id",card.NodeId,"password",password)));using(var sock=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)){
  sock.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(a.Index));sock.Bind(new IPEndPoint(IPAddress.Parse(a.Address),0));sock.ReceiveTimeout=20000;sock.SendTimeout=20000;var pending=sock.BeginConnect("203.0.113.20",443,null,null);if(!pending.AsyncWaitHandle.WaitOne(12000))throw new Exception("连接认证服务超时");sock.EndConnect(pending);
  using(var tls=new SslStream(new NetworkStream(sock,false))){tls.ReadTimeout=20000;tls.WriteTimeout=20000;tls.AuthenticateAsClient("relay.example.invalid",null,System.Security.Authentication.SslProtocols.Tls12,true);var head=Encoding.ASCII.GetBytes("POST /__home_relay_v2/consumer HTTP/1.1\r\nHost: relay.example.invalid\r\nContent-Type: application/json\r\nContent-Length: "+body.Length+"\r\nConnection: close\r\n\r\n");tls.Write(head,0,head.Length);tls.Write(body,0,body.Length);
   using(var m=new MemoryStream()){var buf=new byte[4096];int n;while((n=tls.Read(buf,0,buf.Length))>0){m.Write(buf,0,n);if(m.Length>131072)throw new Exception("认证服务响应过长");}string text=Encoding.UTF8.GetString(m.ToArray());int split=text.IndexOf("\r\n\r\n");if(split<0)throw new Exception("认证服务响应无效");string status=text.Split('\r')[0],payload=text.Substring(split+4);
    if(!status.StartsWith("HTTP/1.1 200")&&!status.StartsWith("HTTP/1.0 200")){if(status.Contains(" 403 ")||status.Contains(" 409 "))throw new SecurityException("节点使用密码错误、授权已撤销，或节点尚未启用。请核对管理面板。");if(status.Contains(" 429 "))throw new SecurityException("连接尝试过多，请一分钟后再试。");throw new Exception("认证服务暂不可用："+status);}
    var cfg=Common.Json.Deserialize<NodeConfig>(payload);ConnectorCore.Validate(cfg);if(cfg.NodeId!=card.NodeId)throw new Exception("认证返回的节点身份不符");return cfg;
   }
  }
 }}
 public static List<NodeConfig> Load(){string p=Path.Combine(Common.Base,"profile","nodes.dpapi");if(!File.Exists(p))return new List<NodeConfig>();var c=Common.Json.Deserialize<List<NodeConfig>>(Common.Unprotect(File.ReadAllBytes(p),"HomeRelayConnector-v3"));foreach(var n in c)Validate(n);return c;}
 public static void Save(List<NodeConfig> cards){foreach(var c in cards)Validate(c);Common.PrivateDir(Path.Combine(Common.Base,"profile"));File.WriteAllBytes(Path.Combine(Common.Base,"profile","nodes.dpapi"),Common.Protect(Common.Json.Serialize(cards),"HomeRelayConnector-v3"));}
}
