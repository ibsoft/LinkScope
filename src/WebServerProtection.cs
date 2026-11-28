using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Xml;
using System.Globalization;

namespace LinkScope {
 // Detection-only supplemental inspection. No script is executed and no raw content leaves the reader.
 internal static class WebServerProtection {
  internal const string NoMatch="No match", Finding="Suspicious web script", Coverage="Web script inspection incomplete", ProcessFinding="Suspicious web server child process", AuditCoverage="Web process audit unavailable", AuditGap="Web process audit history gap";
  internal const int MaxScriptBytes=4*1024*1024;
  static readonly HashSet<string> extensions=new HashSet<string>(new[]{".php",".php3",".php4",".php5",".php7",".php8",".phtml",".phar",".asp",".aspx",".ashx",".asmx",".ascx",".cshtml",".vbhtml",".jsp",".jspx",".cfm",".cfc",".cgi",".pl",".py",".rb",".ps1",".js",".mjs",".cjs",".ts"},StringComparer.OrdinalIgnoreCase);
  internal static bool Selected(EndpointSettings c,string path){return c.WebProtectionEnabled&&c.WebPaths.Any(root=>EndpointProtection.Under(path,root))&&extensions.Contains(Path.GetExtension(path));}
  internal static bool InScope(EndpointSettings c,string path){return c.WebProtectionEnabled&&c.WebPaths.Any(root=>EndpointProtection.Under(path,root))&&!EndpointProtection.Excluded(c,path);}
  static bool Has(string text,string pattern){return Regex.IsMatch(text,pattern,RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(150));}
  internal static string Analyze(string text){
   // Correlation of two independent indicators, not a proof of malicious intent.
   bool input=Has(text,@"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\bRequest\s*(?:\[|\(|\.\s*(?:QueryString|Form|Params|Cookies|InputStream))|\brequest\s*\.\s*(?:getParameter|getInputStream|getReader|args|form|values|json|body|query|headers)\b");
   bool execution=Has(text,@"\b(?:shell_exec|passthru|system|exec|popen|proc_open|pcntl_exec|eval|assert)\s*\(|\b(?:Process\s*\.\s*Start|ProcessStartInfo|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder|WScript\s*\.\s*Shell|subprocess\s*\.\s*(?:Popen|run|call|check_output)|os\s*\.\s*(?:system|popen)|child_process|execSync|spawnSync)\b");
   bool decode=Has(text,@"\b(?:base64_decode|gzinflate|gzuncompress|str_rot13|FromBase64String|atob)\s*\(|\b(?:Base64\s*\.\s*getDecoder|Buffer\s*\.\s*from)\s*\(");
   bool upload=Has(text,@"\b(?:move_uploaded_file|file_put_contents|WriteAllBytes|SaveAs|FileOutputStream)\s*\(");
   var reasons=new List<string>();if(input&&execution)reasons.Add("request input and command/evaluation API");if(decode&&execution)reasons.Add("decoding and command/evaluation API");if(input&&upload&&execution)reasons.Add("request input, file write and execution API");
   return reasons.Count==0?NoMatch:"Review: "+string.Join("; ",reasons);
  }
  internal static string Inspect(Stream file,EndpointReadBudget budget,WaitHandle stop){
   try{
    if(file.Length>MaxScriptBytes)return "Unverified: script exceeds 4 MiB supplemental inspection limit";
    file.Position=0;byte[] bytes=new byte[(int)file.Length];int total=0;
    while(total<bytes.Length){if(stop.WaitOne(0))throw new OperationCanceledException();int n=budget==null?file.Read(bytes,total,bytes.Length-total):budget.Read(file,bytes,total,bytes.Length-total);if(n==0)return "Unverified: short read";total+=n;}
    string text;
    if(bytes.Length>=4&&((bytes[0]==255&&bytes[1]==254&&bytes[2]==0&&bytes[3]==0)||(bytes[0]==0&&bytes[1]==0&&bytes[2]==254&&bytes[3]==255)))return "Unverified: UTF-32 script encoding unsupported";
    if(bytes.Length>=2&&bytes[0]==255&&bytes[1]==254)text=new UnicodeEncoding(false,true,true).GetString(bytes,2,bytes.Length-2);
    else if(bytes.Length>=2&&bytes[0]==254&&bytes[1]==255)text=new UnicodeEncoding(true,true,true).GetString(bytes,2,bytes.Length-2);
    else {if(Array.IndexOf(bytes,(byte)0)>=0)return "Unverified: binary or unsupported script encoding";try{text=new UTF8Encoding(false,true).GetString(bytes);}catch(DecoderFallbackException){text=Encoding.GetEncoding(28591).GetString(bytes);}}
    if(text.IndexOf('\0')>=0)return "Unverified: binary or unsupported script encoding";
    return Analyze(text);
   }catch(OperationCanceledException){throw;}catch(Exception ex){return "Unverified: supplemental inspection "+ex.GetType().Name;}finally{file.Position=0;}
  }
  internal static bool SuspiciousChild(string parent,string child){
   string p=Path.GetFileName(parent??"").ToLowerInvariant(),c=Path.GetFileName(child??"").ToLowerInvariant();
   return new[]{"w3wp.exe","httpd.exe","apache.exe","apache2.exe","php-cgi.exe","php-fpm.exe","nginx.exe","tomcat.exe","tomcat8.exe","tomcat9.exe","tomcat10.exe","tomcat11.exe"}.Contains(p)&&new[]{"cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe"}.Contains(c);
  }
  // Verify the effective process creation success audit policy, not just Security log readability.
  [StructLayout(LayoutKind.Sequential)] struct AuditPolicy {public Guid Subcategory;public uint Flags;public Guid Category;}
  [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy([In] Guid[] ids,uint count,out IntPtr policy);
  [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
  internal static bool QueryProcessAuditPolicy(){IntPtr ptr;if(!AuditQuerySystemPolicy(new[]{new Guid("0cce922b-69ae-11d9-bed3-505054503030")},1,out ptr)||ptr==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),"Cannot query Process Creation audit policy");try{return (((AuditPolicy)Marshal.PtrToStructure(ptr,typeof(AuditPolicy))).Flags&1)!=0;}finally{AuditFree(ptr);}}
  internal static bool ProcessAuditEnabled(){
   try{return QueryProcessAuditPolicy();}
   catch(System.ComponentModel.Win32Exception){if(!Program.ServiceMode)throw;return UsnJournalService.FetchProcessAuditPolicy();}
  }
  internal static string Field(XmlDocument doc,XmlNamespaceManager ns,string name){var node=doc.SelectSingleNode("/e:Event/e:EventData/e:Data[@Name='"+name+"']",ns);return node==null?"":node.InnerText;}
  internal static long? Edge(bool newest){using(var reader=new EventLogReader(new EventLogQuery("Security",PathType.LogName,"*"){ReverseDirection=newest})){reader.BatchSize=1;using(var e=reader.ReadEvent(TimeSpan.FromMilliseconds(500)))return e==null?null:e.RecordId;}}
  internal static string EventFilter(long after,long through){return "*[System[(EventID=4688 or EventID=1102) and EventRecordID > "+after.ToString(CultureInfo.InvariantCulture)+" and EventRecordID <= "+through.ToString(CultureInfo.InvariantCulture)+"]]";}
  internal static XmlDocument EventXml(EventRecord ev,out XmlNamespaceManager ns){var doc=new XmlDocument{XmlResolver=null};doc.LoadXml(ev.ToXml());ns=new XmlNamespaceManager(doc.NameTable);ns.AddNamespace("e","http://schemas.microsoft.com/win/2004/08/events/event");return doc;}
 }
}
