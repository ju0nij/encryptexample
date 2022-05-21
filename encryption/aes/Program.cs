using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace aes
{
    class AES128
    {
        private string key;
        private string iv;
        private int bytelen = 16;
        private int bitlen = 128;

        public AES128()
        {
            key = "abcdefgh12345678";
            iv = "abcdefgh12345678";
        }
        public AES128(string _key)
        {
            key = _key;
            if(key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _key;
            if(iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }
        public AES128(string _key, string _iv)
        {
            key = _key;
            if (key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _iv;
            if (iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }

        public string getKey() { return key; }
        public string getIV() { return iv; }

        public string Encrypt(string textToEncrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            byte[] plainText = Encoding.UTF8.GetBytes(textToEncrypt);
            return Convert.ToBase64String(transform.TransformFinalBlock(plainText, 0, plainText.Length));
        }
        public string Decrypt(string textToDecrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] encryptedData = Convert.FromBase64String(textToDecrypt);
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            byte[] plainText = rijndaelCipher.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return Encoding.UTF8.GetString(plainText);
        }
    }

    class AES192
    {
        private string key;
        private string iv;
        private int bytelen = 24;
        private int bitlen = 192;

        public AES192()
        {
            key = "abcdefgh12345678abcdefgh";
            iv = "abcdefgh12345678";
        }
        public AES192(string _key)
        {
            key = _key;
            if (key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _key;
            if (iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }
        public AES192(string _key, string _iv)
        {
            key = _key;
            if (key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _iv;
            if (iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }

        public string getKey() { return key; }
        public string getIV() { return iv; }

        public string Encrypt(string textToEncrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            byte[] plainText = Encoding.UTF8.GetBytes(textToEncrypt);
            return Convert.ToBase64String(transform.TransformFinalBlock(plainText, 0, plainText.Length));
        }
        public string Decrypt(string textToDecrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] encryptedData = Convert.FromBase64String(textToDecrypt);
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            byte[] plainText = rijndaelCipher.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return Encoding.UTF8.GetString(plainText);
        }
    }

    class AES256
    {
        private string key;
        private string iv;
        private int bytelen = 32;
        private int bitlen = 256;

        public AES256()
        {
            key = "abcdefgh12345678abcdefgh12345678";
            iv = "abcdefgh12345678";
        }
        public AES256(string _key)
        {
            key = _key;
            if (key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _key;
            if (iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }
        public AES256(string _key, string _iv)
        {
            key = _key;
            if (key.Length > bytelen)
            {
                key = key.Substring(0, bytelen);
            }
            iv = _iv;
            if (iv.Length > 16)
            {
                iv = iv.Substring(0, 16);
            }
        }

        public string getKey() { return key; }
        public string getIV() { return iv; }

        public string Encrypt(string textToEncrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            ICryptoTransform transform = rijndaelCipher.CreateEncryptor();
            byte[] plainText = Encoding.UTF8.GetBytes(textToEncrypt);
            return Convert.ToBase64String(transform.TransformFinalBlock(plainText, 0, plainText.Length));
        }
        public string Decrypt(string textToDecrypt)
        {
            RijndaelManaged rijndaelCipher = new RijndaelManaged();
            rijndaelCipher.Mode = CipherMode.CBC;
            rijndaelCipher.Padding = PaddingMode.PKCS7;

            rijndaelCipher.KeySize = bitlen;
            rijndaelCipher.BlockSize = 128;
            byte[] encryptedData = Convert.FromBase64String(textToDecrypt);
            byte[] pwdBytes = Encoding.UTF8.GetBytes(key);
            byte[] pwdivBytes = Encoding.UTF8.GetBytes(iv);
            byte[] keyBytes = new byte[bytelen];
            byte[] ivBytes = new byte[16];
            int keylen = pwdBytes.Length;
            int ivlen = pwdivBytes.Length;
            if (keylen > keyBytes.Length)
            {
                keylen = keyBytes.Length;
            }
            if (ivlen > ivBytes.Length)
            {
                ivlen = ivBytes.Length;
            }
            Array.Copy(pwdBytes, keyBytes, keylen);
            Array.Copy(pwdivBytes, ivBytes, ivlen);
            rijndaelCipher.Key = keyBytes;
            rijndaelCipher.IV = ivBytes;
            byte[] plainText = rijndaelCipher.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return Encoding.UTF8.GetString(plainText);
        }       
    }

    internal class Program
    {
        static void Main(string[] args)
        {
            string key, iv;
            string plaintext, encrypteddata;
            Console.Write("암호화 알고리즘을 선택해주세요(AES128, AES192, AES256): ");
            string text = Console.ReadLine();
            switch(text)
            {
                case "AES128":
                    Console.Write("암호화 키를 입력해주세요(16 byte): ");
                    key = Console.ReadLine();
                    Console.Write("암호화 IV를 입력해주세요(선택, 16 byte): ");
                    iv = Console.ReadLine();
                    AES128 aes128;
                    if (key == "")
                    {
                        aes128 = new AES128();
                    }
                    else if (iv == "")
                    {
                        aes128 = new AES128(key);
                    }
                    else
                    {
                        aes128 = new AES128(key, iv);
                    }
                    Console.WriteLine();
                    Console.Write("암호화 할 텍스트를 입력해주세요: ");
                    plaintext = Console.ReadLine();
                    encrypteddata = aes128.Encrypt(plaintext);
                    Console.WriteLine("AES128 Encrypt: " + encrypteddata);
                    Console.WriteLine("AES128 Decrypt: " + aes128.Decrypt(encrypteddata));
                    break;
                case "AES192":
                    Console.Write("암호화 키를 입력해주세요(24 byte): ");
                    key = Console.ReadLine();
                    Console.Write("암호화 IV를 입력해주세요(선택, 16 byte): ");
                    iv = Console.ReadLine();
                    AES192 aes192;
                    if (key == "")
                    {
                        aes192 = new AES192();
                    }
                    else if (iv == "")
                    {
                        aes192 = new AES192(key);
                    }
                    else
                    {
                        aes192 = new AES192(key, iv);
                    }
                    Console.WriteLine();
                    Console.Write("암호화 할 텍스트를 입력해주세요: ");
                    plaintext = Console.ReadLine();
                    encrypteddata = aes192.Encrypt(plaintext);
                    Console.WriteLine("AES192 Encrypt: " + encrypteddata);
                    Console.WriteLine("AES192 Decrypt: " + aes192.Decrypt(encrypteddata));
                    break;
                case "AES256":
                    Console.Write("암호화 키를 입력해주세요(32 byte): ");
                    key = Console.ReadLine();
                    Console.Write("암호화 IV를 입력해주세요(선택, 16 byte): ");
                    iv = Console.ReadLine();
                    AES256 aes256;
                    if(key == "")
                    {
                        aes256 = new AES256();
                    }
                    else if (iv == "")
                    {
                        aes256 = new AES256(key);
                    }
                    else
                    {
                        aes256 = new AES256(key, iv);
                    }
                    Console.WriteLine();
                    Console.Write("암호화 할 텍스트를 입력해주세요: ");
                    plaintext = Console.ReadLine();
                    encrypteddata = aes256.Encrypt(plaintext);
                    Console.WriteLine("AES256 Encrypt: " + encrypteddata);
                    Console.WriteLine("AES256 Decrypt: " + aes256.Decrypt(encrypteddata));
                    break;
                default:
                    Console.WriteLine("지원하지 않은 형식입니다.");
                    break;
            }
            
        }
    }
}
