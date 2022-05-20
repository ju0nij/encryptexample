using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace protecteddata
{
    //https://docs.microsoft.com/ko-kr/dotnet/api/system.security.cryptography.protecteddata

    class ProtectedDataEx
    {
        public string Protect(string text)
        {
            var PasswordProtect = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(text), null, DataProtectionScope.LocalMachine));
            return PasswordProtect;
        }
        public string Unprotect(string text)
        {
            var PasswordUnprotect = Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(text), null, DataProtectionScope.LocalMachine));
            return PasswordUnprotect;
        }
    }
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Write("변환할 텍스트를 입력해주세요: ");
            ProtectedDataEx protecteddata = new ProtectedDataEx();
            string text = Console.ReadLine();
            string encode = protecteddata.Protect(text);
            Console.WriteLine("Data Encode: " + encode);
            string decode = protecteddata.Unprotect(encode);
            Console.WriteLine("Data Decode: " + decode);
        }
    }
}
