using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace base64
{
    class Base64
    {
        public string EncodeBase64(string text)
        {
            byte[] Byte = Encoding.UTF8.GetBytes(text);
            var data = System.Convert.ToBase64String(Byte);
            return data;
        }
        public string DecodeBase64(string text)
        {
            byte[] Byte = System.Convert.FromBase64String(text);
            var data = Encoding.Default.GetString(Byte);
            return data;
        }
    }
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.Write("변환할 텍스트를 입력해주세요: ");
            Base64 base64 = new Base64();
            string text = Console.ReadLine();
            string encode = base64.EncodeBase64(text);
            Console.WriteLine("Base64 Encode: " + encode);
            string decode = base64.DecodeBase64(encode);
            Console.WriteLine("Base64 Decode: " + decode);
        }
    }
}
