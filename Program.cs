using System.Security.Cryptography;

void FatalErr(string txt)
{
    Console.WriteLine(txt);
    Environment.Exit(1);
}

if (args.Length < 1)
{
    FatalErr("JC2Patch usage:\nJC2Patch.exe <path to JustCause2.exe>\nAt the moment, only supports version 1.0.0.2 as shipped by Steam, no support yet for the DRM-free GOG release.");
}

string jc2Path;
bool bypassMd5 = false;

if (args.Length > 1)
{
    if (args[0].StartsWith("-"))
    {
        jc2Path = args[1];
        if (args[0].ToLowerInvariant() == "--unsafe-bypass-md5-check")
        {
            bypassMd5 = true;
        }
    }
    else
    {
        jc2Path = args[0];
        if (args[1].ToLowerInvariant() == "--unsafe-bypass-md5-check")
        {
            bypassMd5 = true;
        }
    }
}
else
{
    jc2Path = args[0];
}

if (!File.Exists(jc2Path))
{
    FatalErr("Path given does not exist.");
}

const string expectedMd5 = "514167CB2EEEC42EFE9ABFA0FDDCCFCC";

if (!bypassMd5)
{
    using var md5 = MD5.Create();
    using var stream = File.OpenRead(jc2Path);
    byte[] hBytes = md5.ComputeHash(stream);
    string hStr = Convert.ToHexString(hBytes);

    if (hStr != expectedMd5)
    {
        FatalErr($"Your copy of Just Cause 2 is either not the correct version (1.0.0.2, Steam) or has been modified, please source the original executable and try again.\nIf you are sure this is the correct executable, you may pass '--unsafe-bypass-md5-check' to this program.\nExpected MD5: {expectedMd5}\nMD5 of your executable: {hStr}");
    }
}


const uint caveOffsetFo = 0x991520;
const uint brokenMethodOffsetFo = 0x209100;

/*
x86 MC for:
subr:
    test ecx,ecx ; is ecx 0
    jz short fallback ; if so, return fallback

    mov eax, [ecx+224h] ; try read the random CWeapon val
    test eax,eax ; is eax 0
    jz short fallback ; if so, return fallback

    mov eax, [eax+8] ; it's basically guaranteed safe atp
    retn
fallback:
; 0x84 seems to be the globally accepted fallback CWeapon type in anything that uses the broken method, safer better written methods in the game
; that actually check before calling use 0x84, but there are some that do no such checking, which is why the crash occurs in the first place.
    mov eax,84h 
    retn
 */
// No ebytes for this since its all nbyte anyway
byte[] cavePatch = Convert.FromHexString("85C9740E8B812402000085C074048B4008C3B884000000C3");

/*
x86 MC for:
CWeapon__GetDefinitionTypeIdUnsafe:
    push 00D92120h ; VA version of caveOffsetFo
    retn
    nop ; padding since the original method used 10 out of 16 bytes, the rest of the instructions after these NOPs are MSVC's int3 padding.
    nop
    nop
    nop

 */
byte[] subExpect = Convert.FromHexString("8b81240200008b4008c3");
byte[] subPatch = Convert.FromHexString("682021d900c390909090");

byte[] tReadBuf = new byte[256];
((Span<byte>)tReadBuf).Fill(0x67); // Since we are checking for null bytes we don't want false pos's

if (!File.Exists(jc2Path + ".bak"))
{
    File.Copy(jc2Path, jc2Path + ".bak");
}

using var fs = new FileStream(jc2Path, FileMode.Open, FileAccess.ReadWrite);

fs.Seek(caveOffsetFo, SeekOrigin.Begin);
try
{
    fs.ReadExactly(tReadBuf, 0, 24);
    bool isAllNull = tReadBuf.Take(24).All(b => b == 0);
    if (!isAllNull)
    {
        FatalErr($"Error: Cave space is not null!\nCave: {BitConverter.ToString(tReadBuf.AsSpan(0, 24).ToArray()).Replace("-", " ")}");
    }
    else
    {
        fs.Seek(caveOffsetFo, SeekOrigin.Begin);
        fs.Write(cavePatch, 0, 24);
        fs.Flush(true);
        Console.WriteLine("Patched cavespace");
    }
}
catch (EndOfStreamException)
{
    FatalErr("Error: Hit EOF trying to check cave space!");
}

bool CompareFirstNBytes(byte[] array1, byte[] array2, int n)
{
    if (array1.Length < n || array2.Length < n)
    {
        return false;
    }
    ReadOnlySpan<byte> span1 = array1.AsSpan(0, n);
    ReadOnlySpan<byte> span2 = array2.AsSpan(0, n);
    return span1.SequenceEqual(span2);
}

fs.Seek(brokenMethodOffsetFo, SeekOrigin.Begin);
((Span<byte>)tReadBuf).Fill(0x67);
try
{
    fs.ReadExactly(tReadBuf, 0, 10);
    bool iseq = CompareFirstNBytes(tReadBuf, subExpect, 10);
    if (!iseq)
    {
        FatalErr($"Error: Func signature is not expected\ngot {BitConverter.ToString(tReadBuf.AsSpan(0, 10).ToArray()).Replace("-", " ")}\nexpected {BitConverter.ToString(tReadBuf).Replace("-", " ")}");
    }
    else
    {
        fs.Seek(brokenMethodOffsetFo, SeekOrigin.Begin);
        fs.Write(subPatch, 0, 10);
        fs.Flush(true);
        Console.WriteLine("Patched function");
    }
}
catch (EndOfStreamException)
{
    FatalErr("Error: Hit EOF trying to check function!");
}

