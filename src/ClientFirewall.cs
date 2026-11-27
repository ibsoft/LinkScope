using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace LinkScope {
    internal static class ClientFirewall {
        sealed class Rule {
            internal IPAddress Network;
            internal int Prefix;
            internal bool IsSubnet;
            internal string Text { get { return Network.ToString()+(IsSubnet?"/"+Prefix.ToString(CultureInfo.InvariantCulture):""); } }
        }
        static IPAddress Normalize(IPAddress address) {
            return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        }
        static bool Forbidden(IPAddress address) {
            return address.Equals(IPAddress.Any)||address.Equals(IPAddress.IPv6Any)||address.Equals(IPAddress.Broadcast)||address.IsIPv6Multicast||
                (address.AddressFamily==AddressFamily.InterNetwork&&(address.GetAddressBytes()[0]&240)==224);
        }
        static Rule Parse(string entry) {
            string value=(entry??"").Trim();
            if(value.Length==0||value.Length>64||value.Contains("%"))throw new InvalidDataException("Use IPv4, IPv6 or CIDR subnet rules, for example 192.168.1.0/24.");
            string[] parts=value.Split('/');IPAddress address;
            if(parts.Length>2||!IPAddress.TryParse(parts[0],out address))throw new InvalidDataException("Invalid firewall IP address or CIDR subnet.");
            if(address.AddressFamily==AddressFamily.InterNetwork&&parts[0]!=address.ToString())throw new InvalidDataException("Use standard dotted-decimal IPv4 addresses.");
            int prefix=address.GetAddressBytes().Length*8;
            bool subnet=parts.Length==2;
            if(subnet&&(!int.TryParse(parts[1],NumberStyles.None,CultureInfo.InvariantCulture,out prefix)||prefix<1||prefix>address.GetAddressBytes().Length*8))
                throw new InvalidDataException("Invalid CIDR prefix. Use IPv4 /1–/32 or IPv6 /1–/128. /0 is not permitted.");
            if(address.IsIPv4MappedToIPv6){
                if(prefix<=96)throw new InvalidDataException("Use an IPv4 CIDR subnet for IPv4-mapped ranges.");
                prefix-=96;address=Normalize(address);
            }
            if(Forbidden(address))throw new InvalidDataException("Unspecified, broadcast and multicast addresses are not allowed.");
            byte[] bytes=address.GetAddressBytes();
            if(subnet)for(int i=0;i<bytes.Length;i++){
                int bits=Math.Max(0,Math.Min(8,prefix-i*8));
                bytes[i]=(byte)(bytes[i]&(bits==0?0:255<<(8-bits)));
            }
            var network=new IPAddress(bytes);
            if(Forbidden(network))throw new InvalidDataException("Unspecified, broadcast and multicast network bases are not allowed.");
            return new Rule {Network=network,Prefix=prefix,IsSubnet=subnet&&prefix!=bytes.Length*8};
        }
        internal static string[] Validate(string[] entries) {
            entries=entries??new string[0];
            if(entries.Length>256)throw new InvalidDataException("Enter at most 256 allowed IP addresses or CIDR subnets.");
            return entries.Select(entry=>Parse(entry).Text).Distinct(StringComparer.Ordinal).ToArray();
        }
        static bool Matches(IPAddress address,Rule rule) {
            if(address.AddressFamily!=rule.Network.AddressFamily)return false;
            byte[] a=address.GetAddressBytes(),b=rule.Network.GetAddressBytes();
            int whole=rule.Prefix/8,rest=rule.Prefix%8;
            for(int i=0;i<whole;i++)if(a[i]!=b[i])return false;
            return rest==0||((a[whole]^b[whole])&(255<<(8-rest)))==0;
        }
        internal static bool Allows(string peer,string[] entries) {
            IPAddress address;
            if(!IPAddress.TryParse(peer,out address))return false;
            address=Normalize(address);
            if(IPAddress.IsLoopback(address))return true;
            if(Forbidden(address))return false;
            foreach(string entry in entries??new string[0]) {
                try { if(Matches(address,Parse(entry)))return true; }
                catch(InvalidDataException) { /* Malformed rules never grant access. */ }
            }
            return false;
        }
    }
}
