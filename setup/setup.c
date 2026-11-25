/* Offline Windows x64 installer. Win32 imports only; no C runtime.
   build_setup.py embeds the same C# and dashboard sources supplied in the ZIP. */
#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef wchar_t W;
typedef const W *CW;
#define BAD_HANDLE ((HANDLE)(intptr_t)-1)
#define MAXPATH 1024
typedef struct {
    DWORD cb; W *reserved,*desktop,*title; DWORD x,y,xs,ys,xc,yc,fill,flags;
    uint16_t show,reserved2len; unsigned char *reserved2; HANDLE in,out,err;
} STARTUP;
typedef struct { HANDLE process,thread; DWORD pid,tid; } PROCESS;
extern void ExitProcess(DWORD);
extern HANDLE GetStdHandle(DWORD);
extern BOOL WriteFile(HANDLE,const void*,DWORD,DWORD*,void*);
extern BOOL WriteConsoleW(HANDLE,const W*,DWORD,DWORD*,void*);
extern BOOL CloseHandle(HANDLE);
extern DWORD GetWindowsDirectoryW(W*,DWORD);
extern DWORD GetFileAttributesW(CW);
extern BOOL CreateDirectoryW(CW,void*);
extern BOOL RemoveDirectoryW(CW);
extern HANDLE CreateFileW(CW,DWORD,DWORD,void*,DWORD,DWORD,HANDLE);
extern BOOL DeleteFileW(CW);
extern DWORD GetLastError(void);
extern DWORD GetCurrentProcessId(void);
extern DWORD GetTickCount(void);
extern W *GetCommandLineW(void);
extern W **CommandLineToArgvW(CW,int*);
extern HANDLE LocalFree(HANDLE);
extern int32_t SHGetFolderPathW(HANDLE,int,HANDLE,DWORD,W*);
extern BOOL CreateProcessW(CW,W*,void*,void*,BOOL,DWORD,void*,CW,STARTUP*,PROCESS*);
extern DWORD WaitForSingleObject(HANDLE,DWORD);
extern BOOL GetExitCodeProcess(HANDLE,DWORD*);
_Static_assert(sizeof(STARTUP)==104 && sizeof(PROCESS)==24 && sizeof(W)==2,"Windows x64 ABI required");

struct file { CW name; const unsigned char *data; DWORD len; };
#include "payload.h"

static size_t len(CW s) { size_t n=0; while(s[n]) ++n; return n; }
static void say(CW s) {
    HANDLE h=GetStdHandle((DWORD)-11);
    DWORD n=(DWORD)len(s),written=0;
    if(!WriteConsoleW(h,s,n,&written,0)) {
        char ascii[256];
        for(DWORD i=0;i<n;) {
            DWORD k=0;
            while(i<n && k<sizeof(ascii)) { W c=s[i++]; ascii[k++]=c<128?(char)c:'?'; }
            WriteFile(h,ascii,k,&written,0);
        }
    }
}
static void hex(W *out,DWORD value) {
    const W *digits=L"0123456789abcdef";
    for(int i=7;i>=0;i--) { out[i]=digits[value&15]; value>>=4; }
    out[8]=0;
}
static int fail(CW what,DWORD error) {
    W code[9]; hex(code,error); say(what); say(L" (Windows error 0x"); say(code); say(L").\r\n");
    return 1;
}
static int append(W *dst,size_t cap,CW s) {
    size_t i=len(dst),n=len(s); if(i+n>=cap)return 0;
    for(size_t j=0;j<=n;j++)dst[i+j]=s[j];
    return 1;
}
static int setpath(W *dst,CW parent,CW child) {
    dst[0]=0;return append(dst,MAXPATH,parent)&&append(dst,MAXPATH,L"\\")&&append(dst,MAXPATH,child);
}
static int exists(CW path) { return GetFileAttributesW(path)!=0xffffffffu; }
static int equal(CW a,CW b) { while(*a && *a==*b){++a;++b;}return *a==*b; }
static int launch(CW exe,W *cmd,CW cwd) {
    STARTUP si={0}; PROCESS pi={0}; DWORD rc=1; si.cb=sizeof(si);
    if(!CreateProcessW(exe,cmd,0,0,0,0,0,cwd,&si,&pi))return fail(L"Could not start the requested program",GetLastError());
    CloseHandle(pi.thread);WaitForSingleObject(pi.process,0xffffffffu);
    if(!GetExitCodeProcess(pi.process,&rc))rc=1;
    CloseHandle(pi.process);return (int)rc;
}
static W programFiles[MAXPATH],stage[MAXPATH],target[MAXPATH],path[MAXPATH],compiler[MAXPATH],windows[MAXPATH],cmd[4096];
static int install_service(void) {
    cmd[0]=0;
    if(!append(cmd,4096,L"\"")||!append(cmd,4096,target)||!append(cmd,4096,L"\" --install"))return 1;
    return launch(target,cmd,stage);
}
static int install(void) {
    W id[9],ticks[9],subdir[80]=L"LinkScope-build-";
    if(SHGetFolderPathW(0,0x26,0,0,programFiles)<0)return fail(L"Could not locate Program Files",GetLastError());
    DWORD n=GetWindowsDirectoryW(windows,MAXPATH);
    if(n==0||n>=MAXPATH||!setpath(compiler,windows,L"Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe")||!exists(compiler)){
        say(L"The Windows .NET Framework 4.8 x64 compiler is required.\r\n");return 1;
    }
    if(!setpath(path,windows,L"System32\\winsqlite3.dll")||!exists(path)){
        say(L"The Windows SQLite component winsqlite3.dll is required.\r\n");return 1;
    }
    hex(id,GetCurrentProcessId()); hex(ticks,GetTickCount());
    append(subdir,80,id);append(subdir,80,L"-");append(subdir,80,ticks);
    if(!setpath(stage,programFiles,subdir)||!CreateDirectoryW(stage,0))return fail(L"Open an Administrator terminal to prepare the build directory",GetLastError());
    int rc=1;
    for(size_t i=0;i<sizeof(files)/sizeof(files[0]);++i) {
        if(!setpath(path,stage,files[i].name))goto cleanup;
        HANDLE h=CreateFileW(path,0x40000000,0,0,1,0x80,0);
        if(h==BAD_HANDLE){fail(L"Could not unpack source",GetLastError());goto cleanup;}
        DWORD written=0;
        BOOL ok=WriteFile(h,files[i].data,files[i].len,&written,0);
        CloseHandle(h);
        if(!ok||written!=files[i].len){say(L"Could not write full source.\r\n");goto cleanup;}
    }
    say(L"Building the single C# service executable using Windows .NET Framework...\r\n");
    cmd[0]=0;
    if(!append(cmd,4096,L"\"")||!append(cmd,4096,compiler)||!append(cmd,4096,L"\" /nologo /target:exe /platform:x64 /optimize+ /out:LinkScope.exe /reference:System.dll /reference:System.Core.dll /reference:System.Web.dll /reference:System.Web.Extensions.dll /reference:System.Numerics.dll /reference:System.Security.dll /reference:System.ServiceProcess.dll /resource:alerts.html,alerts.html /resource:charts.js,charts.js /resource:logs.html,logs.html /resource:logs.js,logs.js /resource:ai.html,ai.html /resource:loading.js,loading.js /resource:loading.css,loading.css /resource:ai.js,ai.js /resource:ai.css,ai.css /resource:paging.js,paging.js /resource:app.css,app.css /resource:app.js,app.js /resource:security.ps1,security.ps1 /resource:certificate.ps1,certificate.ps1 /resource:dashboard.css,dashboard.css /resource:dashboard.html,dashboard.html /resource:dashboard.js,dashboard.js /resource:default.json,default.json /resource:hardware-task.ps1,hardware-task.ps1 /resource:health.ps1,health.ps1 /resource:login.html,login.html /resource:pdf-lib.min.js,pdf-lib.min.js /resource:report.js,report.js /resource:settings.html,settings.html /resource:smart.ps1,smart.ps1 /resource:system.html,system.html /resource:toast.css,toast.css /resource:toast.js,toast.js *.cs"))goto cleanup;
    rc=launch(compiler,cmd,stage);
    if(rc)goto cleanup;
    if(!setpath(target,stage,L"LinkScope.exe"))rc=1;
    else rc=install_service();
cleanup:
    for(size_t i=0;i<sizeof(files)/sizeof(files[0]);++i)if(setpath(path,stage,files[i].name))DeleteFileW(path);
    if(setpath(path,stage,L"LinkScope.exe"))DeleteFileW(path);
    RemoveDirectoryW(stage);
    return rc;
}
void entry(void) {
    int argc=0;
    W **args=CommandLineToArgvW(GetCommandLineW(),&argc);
    int valid=args && argc==2 && (equal(args[1],L"--install")||equal(args[1],L"-install"));
    if(args)LocalFree(args);
    if(!valid) { say(L"Run from an Administrator terminal: LinkScopeSetup.exe --install\r\n"); ExitProcess(argc==1?0:2); }
    ExitProcess((DWORD)install());
}
