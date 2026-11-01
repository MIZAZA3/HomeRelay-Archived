using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Runtime.InteropServices;
class NetBridge {
 [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(IntPtr h,byte[] b,uint n,out uint done,IntPtr o);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteFile(IntPtr h,byte[] b,uint n,out uint done,IntPtr o);
 static int Main(string[] a) {
  try {
   if(a.Length != 4 || a[2] != "203.0.113.20" || a[3] != "22") throw new Exception("Endpoint not allowed");
   int index=int.Parse(a[0]); IPAddress source=IPAddress.Parse(a[1]);
   using(var s=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)) {
    s.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(index));
    s.Bind(new IPEndPoint(source,0));
    var connect=s.BeginConnect(a[2],22,null,null);
    if(!connect.AsyncWaitHandle.WaitOne(10000)) throw new Exception("SSH connect timeout");
    s.EndConnect(connect);
    s.NoDelay=true;
    IntPtr input=GetStdHandle(-10),output=GetStdHandle(-11);
    var t=new Thread(()=>{try {byte[] b=new byte[65536];uint n;while(ReadFile(input,b,(uint)b.Length,out n,IntPtr.Zero)&&n>0){int off=0;while(off<(int)n)off+=s.Send(b,off,(int)n-off,SocketFlags.None);}s.Shutdown(SocketShutdown.Send);}catch{try{s.Shutdown(SocketShutdown.Both);}catch{}}});
    t.IsBackground=true;t.Start();byte[] data=new byte[65536];int count;
    while((count=s.Receive(data))>0){int off=0;while(off<count){byte[] part;if(off==0)part=data;else{part=new byte[count-off];Buffer.BlockCopy(data,off,part,0,part.Length);}uint written;if(!WriteFile(output,part,(uint)(count-off),out written,IntPtr.Zero)||written==0)throw new IOException("SSH output pipe closed");off+=(int)written;}}
   }
   return 0;
  } catch(Exception e) { Console.Error.WriteLine("SSH transport: "+e.Message); return 1; }
 }
}
