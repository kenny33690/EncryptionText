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
                    break;
                }
                bw.Write(buffer);
                bw.Flush();
            }

            bw.Flush();
            bw.Close();
            fs.Flush();
            fs.Close();
        }


        public static string[] EncryptString(string key, byte[] data)
        {
            var aes = Aes.Create();
            aes.Key = Utils.genKeys(key);
            aes.IV = Utils.genIVs(key);
            aes.Padding = PaddingMode.None;

            var encTrans = aes.CreateEncryptor();
            var buffer = new byte[4096];
            var outBuffer = new byte[4096];
            var dataLength = (int)Math.Ceiling(data.Length / 4096.0);
            List<string> Data = new List<string>(dataLength+1);
            Data.Add(data.Length.ToString());
            var position = 0;
            for (int i = 0; i < dataLength; i++)
            {
                data.CopyTo(buffer, position);
                encTrans.TransformBlock(buffer, 0, buffer.Length, outBuffer, 0);
                Data.Add(Convert.ToBase64String(outBuffer));
                position += 4096;
            }


            return Data.ToArray();
        }
        public static string[] EncryptString(string key, string data)
        {
            return EncryptString(key, Encoding.UTF8.GetBytes(data));
        }

        public static byte[] DecryptString(string key,string[] data)
        {
            var aes = Aes.Create();
            aes.Key = Utils.genKeys(key);
            aes.IV = Utils.genIVs(key);
            aes.Padding = PaddingMode.None;

            var decTrans = aes.CreateDecryptor();
            var bufferSize = 4096;
            var buffer = new byte[bufferSize];
            var outBuffer = new byte[bufferSize];
            var length = int.Parse(data[0]);
            var pos = 0;
            var out_data = new byte[length];

            for (int i = 1; i < data.Length; i++)
            {
                var d1 = Convert.FromBase64String(data[i]);
                d1.CopyTo(buffer, 0);
                decTrans.TransformBlock(buffer,0, buffer.Length, outBuffer, 0);
                if (i == data.Length - 1)
                {
                    Array.Copy(outBuffer, 0, out_data, pos, length%bufferSize);
                    break;
                }
                Array.Copy(buffer, 0, out_data, pos, bufferSize);
                pos += bufferSize;
            }
            return out_data;
        }


    }
}
