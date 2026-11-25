"""Rebuild the offline Windows x64 installer on Linux with GCC, LLVM 19 and GNU binutils.
No library code is linked. Import archives describe standard Windows system DLLs.
The service can also be built directly on Windows with the supplied Build.cmd.
"""
from pathlib import Path
import ctypes as ct
import ctypes.util
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = root / "setup" / "setup.c"
apis = {
    "KERNEL32": """ExitProcess GetStdHandle WriteFile WriteConsoleW CloseHandle GetWindowsDirectoryW
                   GetFileAttributesW CreateDirectoryW RemoveDirectoryW CreateFileW DeleteFileW
                   GetLastError GetCurrentProcessId GetTickCount GetCommandLineW LocalFree CreateProcessW
                   WaitForSingleObject GetExitCodeProcess""".split(),
    "SHELL32": ["CommandLineToArgvW", "SHGetFolderPathW"],
}

def assemble_coff(assembly, outfile):
    """Assemble x64 instructions and symbol references directly for Windows COFF."""
    llvm = ct.CDLL(ctypes.util.find_library("LLVM-19") or "libLLVM-19.so")
    P, S, I = ct.c_void_p, ct.c_char_p, ct.c_int
    def api(name, result, args):
        fn = getattr(llvm, "LLVM" + name)
        fn.restype, fn.argtypes = result, args
        return fn
    for name in ("TargetInfo", "Target", "TargetMC", "AsmParser", "AsmPrinter"):
        api("InitializeX86" + name, None, [])()
    ctx = api("ContextCreate", P, [])()
    module = api("ModuleCreateWithNameInContext", P, [S, P])(b"setup", ctx)
    triple = b"x86_64-pc-windows-msvc"
    api("SetTarget", None, [P, S])(module, triple)
    raw = assembly.encode()
    api("SetModuleInlineAsm2", None, [P, S, ct.c_size_t])(module, raw, len(raw))
    target, error = P(), S()
    if api("GetTargetFromTriple", I, [S, ct.POINTER(P), ct.POINTER(S)])(triple, ct.byref(target), ct.byref(error)):
        raise RuntimeError(error.value)
    machine = api("CreateTargetMachine", P, [P,S,S,S,I,I,I])(target,triple,b"x86-64",b"",2,0,0)
    if api("TargetMachineEmitToFile", I, [P,P,S,I,ct.POINTER(S)])(machine,module,str(outfile).encode(),1,ct.byref(error)):
        raise RuntimeError(error.value)
    api("DisposeTargetMachine", None, [P])(machine)
    api("DisposeModule", None, [P])(module)
    api("ContextDispose", None, [P])(ctx)

with tempfile.TemporaryDirectory() as tmp:
    work = Path(tmp)
    def run(*args):
        subprocess.run(args, cwd=work, check=True)
    chunks, entries = [], []
    for f in sorted((root / "src").iterdir()):
        if f.suffix not in (".cs", ".html", ".json", ".js", ".css", ".ps1", ".css", ".ps1", ".css", ".ps1"):
            continue
        name = "data_" + re.sub(r"\W", "_", f.name)
        # Arrays use numeric byte literals to preserve UTF-8 and avoid escaping.
        arr = ",".join(map(str, f.read_bytes()))
        chunks.append(f"static const unsigned char {name}[]={{ {arr} }};")
        entries.append(f'{{L"{f.name}",{name},sizeof({name})}}')
    (work / "payload.h").write_text("\n".join(chunks) + "\nstatic const struct file files[]={" + ",".join(entries) + "};\n")
    # Generate import archives. The stub DLLs are build intermediates only.
    for dll, symbols in apis.items():
        (work / "exports.s").write_text(".text\n" + "\n".join(f".global {s}\n{s}: ret" for s in symbols) + "\n")
        (work / "exports.def").write_text(f"LIBRARY {dll}.dll\nEXPORTS\n" + "\n".join(symbols) + "\n")
        run("as", "--64", "-o", "exports.elf", "exports.s")
        run("objcopy", "-O", "pe-x86-64", "exports.elf", "exports.obj")
        run("ld", "-mi386pep", "--shared", "-e", "0", "-o", dll+".dll", "--out-implib", "lib"+dll+".a", "exports.obj", "exports.def")
    run("gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-fno-stack-protector", "-fno-ident",
        "-fno-jump-tables", "-mabi=ms", "-mno-red-zone", "-fshort-wchar", "-fpie", "-fno-merge-constants",
        "-I", str(work), "-S", str(source), "-o", "setup.s")
    asm = (work / "setup.s").read_text()
    asm = re.sub(r'^\s*\.(?:file|type|size|local)\s+.*$', '', asm, flags=re.M)
    asm = re.sub(r'^\s*\.section\s+\.note\.GNU-stack.*$', '', asm, flags=re.M)
    asm = re.sub(r'^\s*\.section\s+\.(?:rodata|data\.rel\.ro)[^\n]*','\n.section .rdata,"dr"',asm,flags=re.M)
    # ELF .comm takes byte alignment; COFF .comm takes log2(alignment).
    asm = re.sub(r'(\.comm\s+[^,]+,\d+,)(\d+)', lambda m: m[1]+str(int(m[2]).bit_length()-1), asm)
    assemble_coff(asm.replace("@PLT", ""), work / "setup.obj")
    run("ld","-mi386pep","--image-base","0x400000","--subsystem","console:6.0","--dynamicbase","--nxcompat",
        "--enable-reloc-section","--file-alignment","512","--no-insert-timestamp","-e","entry","-s",
        "-o",str(root/"LinkScopeSetup.exe"),"setup.obj","libKERNEL32.a","libSHELL32.a")
