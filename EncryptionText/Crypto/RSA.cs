using SharpConfig;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionText.Crypto
{
    internal class RSACrypto : BaseCrypto
    {


        public static RSACrypto Create(string fileName, bool isEncrypt)
        {
            return new RSACrypto(fileName, isEncrypt);
        }
        public RSACrypto(string fileName, bool isEncrypt = true)
        {

            base.Method = "RSA";
            base.Version = "0.0.1";
            base.BufferSize = 128;
            if (isEncrypt)
            {
                SourceFileName = fileName;
                var parDir = Path.GetDirectoryName(SourceFileName);
                var encFile = Path.Combine(parDir, Path.GetFileName(SourceFileName) + ".enc");
                SourceLength = (int)new FileInfo(SourceFileName).Length;
                EncryptFileName = encFile;
            }
            else
            {
                EncryptFileName = fileName;
            }
        }
    

        public static string GenKeys(int keysize = 2048)
        {
            using (var rsa = new RSACryptoServiceProvider(keysize))
            {
                return rsa.ToXmlString(true);
            }
        }
        public static bool IsKey(string key)
        {
            return key.StartsWith("<RSAKeyValue>");
        }

        public override void Decrypt(string key)
        {

            string rsaKey;
            if (!IsKey(key))
            {
                Load();
                //rsaKey = GenKeys();
                rsaKey = RsaKey;
            }
            else
            {
                base.Load();
                rsaKey = key;
            }
            var fileName = SourceFileName;
            var parDir = Path.GetDirectoryName(EncryptFileName);
            var origin = Path.Combine(parDir,"origin_"+ Path.GetFileName(fileName));
            var fs = new FileStream(origin, FileMode.Create);
            var bw = new BinaryWriter(fs);
            var buffer = new byte[BufferSize];


            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(rsaKey);

                for (int i = 0; i < Length; i++)
                {
                    var baseByte = Convert.FromBase64String(Data[i]);

                    var buf = rsa.Decrypt(baseByte, true);

                    if (i == Length - 1)
                    {
                        bw.Write(buf, 0, SourceLength % BufferSize);
                        break;
                    }

                    bw.Write(buf);
                }


            }
            bw.Flush();
            bw.Close();
            fs.Close();

        }

        public override void Encrypt(string key)
        {
            bool flag = true;
            string rsaKey;
            if (!IsKey(key))
            {
                rsaKey = GenKeys();
                flag = false;
            }
            else
            {
                rsaKey = key;
            }
            var filename = SourceFileName;
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(rsaKey);


                var fs1 = new FileStream(filename, FileMode.Open);
                var br = new BinaryReader(fs1);
                byte[] buffer = new byte[BufferSize];
                byte[] out_buffer;
                List<string> baseString = new List<string>(SourceLength / BufferSize);
                int num;
                while ((num = br.Read(buffer, 0, buffer.Length)) > 0)
                {
                    if (num != BufferSize)
                    {
                        Console.WriteLine(br.BaseStream.Position);
                        for (int i = 0; i < BufferSize - num; i++)
                        {
                            buffer[num + i] = 0;
                        }
                    }
                    out_buffer = rsa.Encrypt(buffer,true);
                    baseString.Add(Convert.ToBase64String(out_buffer));

                }
                Data = baseString;
                br.Close();
                fs1.Close();

            }

            RsaKey = rsaKey;
            IsHaveKey = flag;
            Key = key;
        }
        private string RsaKey = "";
        private string Key = "";
        private bool IsHaveKey = false;
        public override void Save()
        {
            var encFileName = EncryptFileName;
            var data = Data;
            var flag = IsHaveKey;
            

            var conf = BaseConf(encFileName, data);
            if (flag)
            {
                conf.SaveToFile(encFileName);
                return;
            }
            else
            {
                var sec3 = new Section("Key");
                var keydata = AES.EncryptString(Key, RsaKey);

                sec3.Add("Length", keydata[0]);
                for (int i = 1; i < keydata.Length; i++)
                {
                    sec3.Add(i.ToString(), keydata[i]);
                }

                conf.Add(sec3);
                conf.SaveToFile(encFileName);
            }
            

        }

        public override void Load()
        {
            base.Load();
            if (!IsHaveKey)
            {
                var secKey = Config["Key"];
                var settingLen = secKey.Count();
                var data = new string[settingLen];
                for (int i = 0; i < settingLen; i++)
                {
                    data[i] = secKey[i].StringValue;
                }

                var @byte = AES.DecryptString(Key, data);
                var rsaKey = Encoding.UTF8.GetString(@byte);
                if (!IsKey(rsaKey))
                {
                    throw new CryptographicException("解密错误");
                }
                RsaKey = rsaKey;
            }
            

            
        }
    }
}
