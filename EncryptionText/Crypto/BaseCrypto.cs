using System.Collections.Generic;
using SharpConfig;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using EncryptionText.Crypto;
using System.Reflection.Emit;

namespace EncryptionText
{
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

        public Configuration BaseConf(string encFileName, List<string> data)
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

            return conf;
        }

        /// <summary>
        /// 加密保存
        /// </summary>
        /// <param name="encFileName">保存后加密文件路径</param>
        /// <param name="data">加密数据</param>
        public void Save(string encFileName, List<string> data)
        {
            var conf = BaseConf(encFileName, data);

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

        public static string GetMethodFromFile(string path)
        {
            var conf = Configuration.LoadFromFile(path);
            var sec1 = conf["Conf"];
            return sec1["Method"].StringValue;
        }

        public abstract void Encrypt(string key);
        public abstract void Decrypt(string key);

        public delegate BaseCrypto Constructor(string FileName,bool isEncrypt);
    }
}
