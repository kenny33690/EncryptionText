using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using SharpConfig;
using System.IO;
using System.ComponentModel.Design;
using System.Xml.Schema;
using System.Threading;

namespace EncryptionText
{
    internal class AesEncryptor : BaseCrypto
    {

        public AesEncryptor(string sf)
        {
            SourceFileName = sf;
            Version = "0.0.1";
            Method = "Aes";

        }



        public void Encrypt(string key)
        {
            string filename = SourceFileName;
            var parDir = Path.GetDirectoryName(filename);
            var encFile = Path.Combine(parDir, Path.GetFileName(filename) + ".enc");
            SourceLength = (int)(new FileInfo(filename)).Length;

            var aes = Aes.Create();
            aes.Key = Utils.genKeys(key);
            aes.IV = Utils.genIVs(key);
            aes.Padding = PaddingMode.None;
            var encTrans = aes.CreateEncryptor();

            var fs1 = new FileStream(filename, FileMode.Open);
            var br = new BinaryReader(fs1);
            byte[] buffer = new byte[BufferSize];
            byte[] out_buffer = new byte[BufferSize];
            List<string> baseString = new List<string>((int)SourceLength / BufferSize);
            int num;
            while ((num = br.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (num != BufferSize)
                {
                    Console.WriteLine(br.BaseStream.Position);
                    for (int i = 0; i < BufferSize-num; i++)
                    {
                        buffer[num + i] = 0;
                    }
                }
                encTrans.TransformBlock(buffer, 0, buffer.Length, out_buffer, 0);
                baseString.Add(Convert.ToBase64String(out_buffer));

            }
            //bw.Flush();
            br.Close();
            //bw.Close();
            fs1.Close();
            //fs2.Close();
            Save(encFile, baseString);
        }


    }

    internal class AesDecryptor : BaseCrypto
    {
        public AesDecryptor(string sf)
        {
            EncryptFileName = sf;
            Version = "0.0.1";
            Method = "Aes";

        }

        public void Decrypt(string key)
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
                if (i==Length-1)
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
            fs.Dispose();
        }



        

    }
    abstract class BaseCrypto
    {
        /// <summary>
        /// 源文件名
        /// </summary>
        public string SourceFileName;
        /// <summary>
        /// 源文件大小
        /// </summary>
        public int SourceLength;
        /// <summary>
        /// 加密后文件名
        /// </summary>
        public string EncryptFileName;
        /// <summary>
        /// 加密方式
        /// </summary>
        public string Method;
        /// <summary>
        /// 加密程序版本
        /// </summary>
        public string Version;
        /// <summary>
        /// 源文件Hash
        /// </summary>
        public string Hash;

        /// <summary>
        /// 加密串长度
        /// </summary>
        public int Length;
        /// <summary>
        /// 加密串数据
        /// </summary>
        public List<string> Data;
        /// <summary>
        /// 缓冲区长度
        /// </summary>
        public int BufferSize = 4096;

        /// <summary>
        /// 加密保存
        /// </summary>
        /// <param name="encFileName">保存后加密文件路径</param>
        /// <param name="data">加密数据</param>
        public void Save(string encFileName, List<string> data)
        {
            var conf = new Configuration();
            var sec1 = new Section("Conf");

            var onlyFileName = Path.GetFileName(SourceFileName);

            sec1.Add("SourceFileName", onlyFileName);
            sec1.Add("Method", Method);
            sec1.Add("Version", Version);
            sec1.Add("SourceLength", SourceLength);

            var sec2 = new Section("Encrypt");
            sec2.Add("Length", data.Count);
            for (int i = 0; i < data.Count; i++)
            {
                sec2.Add(i.ToString(), data[i]);
            }
            conf.Add(sec1);
            conf.Add(sec2);

            conf.SaveToFile(encFileName);
        }

        /// <summary>
        /// 加载加密文件
        /// </summary>
        public void Load()
        {
            var conf = Configuration.LoadFromFile(EncryptFileName);
            var sec1 = conf["Conf"];
            var sec2 = conf["Encrypt"];


            SourceFileName = sec1["SourceFileName"].RawValue;
            Length = sec2["Length"].IntValue;
            Data = new List<string>(Length);
            SourceLength = sec1["SourceLength"].IntValue;

            for (int i = 0; i < Length; i++)
            {
                Data.Add(sec2[i.ToString()].StringValue);
            }
        }
    }
}
