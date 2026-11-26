using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace LinkScope {
    internal static class ClientFirewall {
        static IPAddress Normalize(IPAddress address) {
            return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        }
        internal static string[] Validate(string[] entries) {
            entries=entries??new string[0];
            if(entries.Length>256)throw new InvalidDataException("Enter at most 256 allowed client IP addresses.");
            return entries.Select(entry=>{
                IPAddress address;
                string value=(entry??"").Trim();
                if(value.Length==0||value.Length>64||value.Contains("%")||!IPAddress.TryParse(value,out address))
                    throw new InvalidDataException("Use individual IPv4 or IPv6 addresses in the firewall allowlist.");
                if(address.AddressFamily==AddressFamily.InterNetwork && value!=address.ToString())
                    throw new InvalidDataException("Use standard dotted-decimal IPv4 addresses.");
                address=Normalize(address);
                if(address.Equals(IPAddress.Any)||address.Equals(IPAddress.IPv6Any)||address.Equals(IPAddress.Broadcast)||address.IsIPv6Multicast||
                    (address.AddressFamily==AddressFamily.InterNetwork && (address.GetAddressBytes()[0]&240)==224))
                    throw new InvalidDataException("Unspecified, broadcast and multicast addresses are not allowed.");
                return address.ToString();
            }).Distinct().ToArray();
        }
        internal static bool Allows(string peer,string[] entries) {
            IPAddress address;
            if(!IPAddress.TryParse(peer,out address))return false;
            address=Normalize(address);
            return IPAddress.IsLoopback(address)||(entries??new string[0]).Contains(address.ToString(),StringComparer.Ordinal);
        }
    }
}
