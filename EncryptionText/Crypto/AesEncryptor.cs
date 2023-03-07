using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.ComponentModel.Design;
using System.Xml.Schema;
using System.Threading;
using System.Reflection;

namespace EncryptionText.Crypto
{
    internal class AES : BaseCrypto
    {
        string Method = "AES";
        string Version = "0.0.1";
        
        public static AES Create(string fileName, bool isEncrypt)
        {
            return new AES(fileName, isEncrypt);
        }
        public AES(string fileName, bool isEncrypt = true)
        {

            base.Method = "AES";
            base.Version = "0.0.1";
            if (isEncrypt)
            {
                SourceFileName = fileName;
            }
            else
            {
                EncryptFileName = fileName;
            }
        }





        public override void Encrypt(string key)
        {
            string filename = SourceFileName;
            var parDir = Path.GetDirectoryName(filename);
            var encFile = Path.Combine(parDir, Path.GetFileName(filename) + ".enc");
            SourceLength = (int)new FileInfo(filename).Length;
            EncryptFileName = encFile;

            var aes = Aes.Create();
            aes.Key = Utils.genKeys(key);
            aes.IV = Utils.genIVs(key);
            aes.Padding = PaddingMode.None;
            var encTrans = aes.CreateEncryptor();

            var fs1 = new FileStream(filename, FileMode.Open);
            var br = new BinaryReader(fs1);
            byte[] buffer = new byte[BufferSize];
            byte[] out_buffer = new byte[BufferSize];
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
                encTrans.TransformBlock(buffer, 0, buffer.Length, out_buffer, 0);
                baseString.Add(Convert.ToBase64String(out_buffer));

            }
            br.Close();
            fs1.Close();
            Data = baseString;
            Save(encFile, baseString);
        }

        public override void Decrypt(string key)
        {
            Load();

            var aes = Aes.Create();
            aes.Key = Utils.genKeys(key);
            aes.IV = Utils.genIVs(key);
            aes.Padding = PaddingMode.None;
            var decTrans = aes.CreateDecryptor();
            var parDir = Path.GetDirectoryName(EncryptFileName);

            var origin = Path.Combine(parDir, "origin_" + SourceFileName);
            var fs = new FileStream(origin, FileMode.Create);
            var bw = new BinaryWriter(fs);
            var buffer = new byte[BufferSize];


            for (int i = 0; i < Length; i++)
            {
                var baseByte = Convert.FromBase64String(Data[i]);
                decTrans.TransformBlock(baseByte, 0, baseByte.Length, buffer, 0);
                if (i == Length - 1)
                {
                    bw.Write(buffer, 0, SourceLength % BufferSize);
                    return;
                }
                bw.Write(buffer);
                bw.Flush();
            }

            bw.Flush();
            bw.Close();
            fs.Flush();
            fs.Close();
        }
    }
}
