using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Linq;
namespace LinkScope {
    static class NativeConnections {
        sealed class EndpointRow {
            public string protocol {get;set;} public string local {get;set;} public string remote {get;set;} public string state {get;set;}
        }
        public static object Snapshot() {
            var ip=IPGlobalProperties.GetIPGlobalProperties();
            var rows=new List<EndpointRow>();
            foreach(var c in ip.GetActiveTcpConnections()) rows.Add(new EndpointRow{protocol="TCP",local=c.LocalEndPoint.ToString(),remote=c.RemoteEndPoint.ToString(),state=c.State.ToString()});
            foreach(var e in ip.GetActiveTcpListeners()) rows.Add(new EndpointRow{protocol="TCP",local=e.ToString(),remote="—",state="Listen"});
            foreach(var e in ip.GetActiveUdpListeners()) rows.Add(new EndpointRow{protocol="UDP",local=e.ToString(),remote="—",state="Bound"});
            return new {now=History.Now(),total=rows.Count,rows=rows.Take(2000).ToArray()};
        }
    }
}
