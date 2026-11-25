using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace LinkScope {
    // The scheduled hardware reader has no listener and reads no web configuration.
    // Its ATA requests are fixed SMART READ DATA and SMART READ THRESHOLDS commands.
    internal static class SmartDisk {
        const uint StorageQuery=0x002D1400;
        [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
        static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr sa,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)]
        static extern bool DeviceIoControl(SafeFileHandle h,uint code,[In]byte[] input,int inputSize,[Out]byte[] output,int outputSize,out int returned,IntPtr overlapped);
        static SafeFileHandle Open(int i,uint access){return CreateFile(@"\\.\PhysicalDrive"+i,access,7,IntPtr.Zero,3,0,IntPtr.Zero);}
        static bool Query(SafeFileHandle h,uint code,byte[] input,byte[] output,out int n){return DeviceIoControl(h,code,input,input.Length,output,output.Length,out n,IntPtr.Zero);}
        static void U32(byte[] b,int p,uint x){BitConverter.GetBytes(x).CopyTo(b,p);}
        static string Ascii(byte[] b,int field,int count){uint n=BitConverter.ToUInt32(b,field);if(n<36||n>=count)return "";int i=(int)n,end=i;while(end<count&&end<i+256&&b[end]!=0)end++;return Encoding.ASCII.GetString(b,i,end-i).Trim();}
        static string Bus(uint n){switch(n){case 1:return "SCSI";case 3:return "ATA";case 7:return "USB";case 8:return "RAID";case 10:return "SAS";case 11:return "SATA";case 14:return "Virtual";case 15:return "File-backed";case 16:return "Storage Spaces";case 17:return "NVMe";default:return "Bus "+n;}}
        static byte[] ValidPage(byte[] bytes,int offset){var page=new byte[512];Array.Copy(bytes,offset,page,0,512);
            if((page[0]==0&&page[1]==0)||(page.Sum(x=>(int)x)&255)!=0||!Enumerable.Range(0,30).Any(i=>page[2+12*i]>0&&page[2+12*i]<255))return null;return page;}
        static byte[] AtaPage(SafeFileHandle h,byte feature,out string source){
            source="SMART_RCV_DRIVE_DATA";var input=new byte[33];var reply=new byte[528];int n;
            U32(input,0,512);input[4]=feature;input[5]=input[6]=1;input[7]=0x4f;input[8]=0xc2;input[9]=0xa0;input[10]=0xb0;
            if(Query(h,0x0007c088,input,reply,out n)&&n>=528&&reply[4]==0&&reply[5]==0){var data=ValidPage(reply,16);if(data!=null)return data;}
            source="ATA_PASS_THROUGH";input=new byte[48];reply=new byte[1024];
            input[0]=48;input[2]=2;U32(input,8,512);U32(input,12,5);U32(input,24,512);
            input[40]=feature;input[41]=input[42]=1;input[43]=0x4f;input[44]=0xc2;input[45]=0xa0;input[46]=0xb0;
            if(Query(h,0x0004d02c,input,reply,out n)&&n>=1024&&BitConverter.ToUInt32(reply,8)>=512&&(reply[46]&0xa1)==0)return ValidPage(reply,512);
            source="unavailable";return null;
        }
        static readonly Dictionary<int,string> General=new Dictionary<int,string>{
            {5,"Reallocated / retired sectors"},{9,"Power-on hours (vendor-specific)"},{12,"Power-cycle count"},{170,"Available reserved space (vendor-specific)"},{171,"Program failures (vendor-specific)"},{172,"Erase failures (vendor-specific)"},{173,"Wear leveling (vendor-specific)"},{174,"Unexpected power losses (vendor-specific)"},{177,"Wear-leveling count (vendor-specific)"},{179,"Used reserved blocks (vendor-specific)"},{181,"Program fail count (vendor-specific)"},{182,"Erase fail count (vendor-specific)"},{187,"Reported uncorrectable errors"},{188,"Command timeouts"},{190,"Temperature / airflow (vendor-specific)"},{194,"Temperature (vendor-specific)"},{196,"Reallocation events"},{197,"Current pending sectors"},{198,"Offline uncorrectable sectors"},{199,"Interface CRC errors"},{202,"Lifetime / wear indicator (vendor-specific)"},{231,"SSD life / temperature (vendor-specific)"},{232,"Available reserved space (vendor-specific)"},{233,"Media wearout indicator (vendor-specific)"},{241,"Lifetime host writes (vendor-specific)"},{242,"Lifetime host reads (vendor-specific)"}};
        static readonly Dictionary<int,string> Samsung=new Dictionary<int,string>{
            {5,"Reallocation Sector Count"},{9,"Power-On Hours Count"},{12,"Device Power Cycle Count"},{177,"Wear Leveling Count"},{179,"Used Rsvd Block Count Total"},{181,"Program Fail Count Total"},{182,"Erase Fail Count Total"},{183,"Runtime Bad Block"},{187,"Reported Uncorrectable Error"},{190,"Airflow Temperature"},{195,"ECC Rate"},{199,"UltraDMA CRC Errors Count"},{235,"POR Recovery Count"},{241,"Total Host Writes"}};
        internal static List<object> Attributes(byte[] data,byte[] thresholds,bool samsung){
            var rows=new List<object>();if(data==null)return rows;var limits=new Dictionary<int,int>();
            if(thresholds!=null)for(int i=2;i<362;i+=12)limits[thresholds[i]]=thresholds[i+1];
            for(int i=2;i<362;i+=12){int id=data[i];if(id==0||id==255)continue;
                ulong raw=0;for(int b=0;b<6;b++)raw|=(ulong)data[i+5+b]<<(8*b);string h=raw.ToString("X12");
                int t;int? threshold=limits.TryGetValue(id,out t)?(int?)t:null;int value=data[i+3];
                string name;if(!(samsung&&Samsung.TryGetValue(id,out name))&&!General.TryGetValue(id,out name))name="Vendor-specific attribute";
                string state=threshold>0&&value<=threshold?"FAIL":raw>0&&new[]{5,187,197,198,199}.Contains(id)?"REVIEW":threshold.HasValue?"OK":"UNKNOWN";
                rows.Add(new {state=state,id=id,name=name,value=value,worst=(int)data[i+4],rawHex=h.Substring(0,8)+"-"+h.Substring(8),rawDecimal=raw.ToString(CultureInfo.InvariantCulture),threshold=threshold});
            }return rows;
        }
        static string Counter(byte[] b,int p){var wide=new byte[17];Array.Copy(b,p,wide,0,16);return new BigInteger(wide).ToString(CultureInfo.InvariantCulture);}
        static object Nvme(SafeFileHandle h){
            var input=new byte[560];var output=new byte[560];int n;U32(input,0,50);U32(input,8,3);U32(input,12,2);U32(input,16,2);U32(input,24,40);U32(input,28,512);
            if(!Query(h,StorageQuery,input,output,out n)||n<560||BitConverter.ToUInt32(output,0)<48||BitConverter.ToUInt32(output,8)!=3||
                BitConverter.ToUInt32(output,12)!=2||BitConverter.ToUInt32(output,24)!=40||BitConverter.ToUInt32(output,28)<512)return null;
            const int p=48;if(!output.Skip(p).Any(x=>x!=0)||output[p+3]>100||output[p+4]>100)return null;
            int kelvin=BitConverter.ToUInt16(output,p+1);
            return new {criticalWarning=(int)output[p],temperatureC=kelvin>=200&&kelvin<=600?(int?)(kelvin-273):null,availableSparePercent=(int)output[p+3],spareThresholdPercent=(int)output[p+4],percentageUsed=(int)output[p+5],
                dataUnitsRead=Counter(output,p+32),dataUnitsWritten=Counter(output,p+48),powerCycles=Counter(output,p+112),powerOnHours=Counter(output,p+128),unsafeShutdowns=Counter(output,p+144),mediaErrors=Counter(output,p+160),errorLogEntries=Counter(output,p+176)};
        }
        static object Read(int index,SafeFileHandle h){
            var resp=new byte[4096];int n;string model="Physical disk "+index,vendor="",fw="",serial="",bus="Unknown";
            if(Query(h,StorageQuery,new byte[12],resp,out n)&&n>=36){
                vendor=Ascii(resp,12,n);string product=Ascii(resp,16,n);if(product.Length>0)model=((vendor=="ATA"?"":vendor)+" "+product).Trim();
                fw=Ascii(resp,20,n);serial=Ascii(resp,24,n);bus=Bus(BitConverter.ToUInt32(resp,28));}
            bool samsung=model.IndexOf("Samsung SSD",StringComparison.OrdinalIgnoreCase)>=0;
            if(samsung)vendor="Samsung";else if(vendor=="ATA")vendor="";
            long? capacity=null;var size=new byte[8];using(var rh=Open(index,0x80000000)){
                if(!rh.IsInvalid&&Query(rh,0x0007405c,new byte[0],size,out n)&&n>=8)capacity=BitConverter.ToInt64(size,0);}
            var pred=new byte[516];bool? prediction=null;
            if(Query(h,0x002d1100,new byte[0],pred,out n)&&n>=516)prediction=BitConverter.ToUInt32(pred,0)!=0;
            object nvme=null;byte[] data=null,thresholds=null;var diagnostics=new List<string>();string source="unavailable";
            if(bus=="NVMe"){
                nvme=Nvme(h);if(nvme!=null)source="NVMe health log 0x02";else diagnostics.Add("Controller did not return a complete NVMe health log.");
            }else if(new[]{"SCSI","ATA","SATA","USB","RAID"}.Contains(bus)){
                using(var sh=Open(index,0xc0000000)){if(!sh.IsInvalid){data=AtaPage(sh,0xd0,out source);if(data!=null){string dummy;thresholds=AtaPage(sh,0xd1,out dummy);}}}
                if(data==null)diagnostics.Add("Drive or controller did not expose a validated ATA SMART data page.");
                else if(thresholds==null)diagnostics.Add("Manufacturer thresholds unavailable.");
            }else diagnostics.Add("Raw SMART pass-through is unavailable for this bus.");
            return new {device=index.ToString(CultureInfo.InvariantCulture),model=model,vendor=vendor,firmware=fw,serial=serial,capacityBytes=capacity,bus=bus,
                scanUtc=DateTime.UtcNow.ToString("o"),smartSource=source,predictFailure=prediction,attributes=Attributes(data,thresholds,samsung),nvme=nvme,diagnostics=diagnostics};
        }
        internal static void Capture(){
            var rows=new List<object>();for(int i=0;i<256;i++)using(var h=Open(i,0)){if(!h.IsInvalid)rows.Add(Read(i,h));}
            Config.Save(Path.Combine(Config.Root,"hardware.json"),new {scannedUtc=DateTime.UtcNow.ToString("o"),disks=rows});
        }
    }
}
