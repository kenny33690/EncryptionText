﻿using SharpConfig;
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
            
            throw new NotImplementedException();
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
                rsa.FromXmlString(key);


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
                    out_buffer = rsa.Encrypt(buffer, RSAEncryptionPadding.OaepSHA256);
                    baseString.Add(Convert.ToBase64String(out_buffer));

                }

                br.Close();
                fs1.Close();

            }

            
        }

        public void Save(string encFileName, List<string> data,bool flag,string key)
        {
            var conf = BaseConf(encFileName, data);
            if (flag)
            {
                conf.SaveToFile(encFileName);
                return;
            }

            var sec3 = new Section("Key");
            
        }
    }
}
