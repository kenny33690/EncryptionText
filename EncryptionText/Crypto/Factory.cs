using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionText.Crypto
{
    class CryptoFactory
    {
        private static Dictionary<string, BaseCrypto.Constructor> _crypto = new Dictionary<string, BaseCrypto.Constructor>();
        /// <summary>
        /// 初始化
        /// </summary>
        static CryptoFactory()
        {
            _crypto.Add("AES", new BaseCrypto.Constructor(AES.Create));
            _crypto.Add("RSA", new BaseCrypto.Constructor(RSACrypto.Create));
        }

        public static void RegisterCrypto(string Method, BaseCrypto.Constructor func)
        {
            if (string.IsNullOrEmpty(Method))
            {
                return;
            }
            _crypto.Add(Method, func);
        }

        public static BaseCrypto CreateCrypto(string FilePath, bool isEncrypt = true, string Method = null)
        {
            if (string.IsNullOrEmpty(Method))
            {
                Method = BaseCrypto.GetMethodFromFile(FilePath);
                if (string.IsNullOrEmpty(Method))
                {
                    throw new ArgumentException("加密方式不能为空");
                }
            }
            try
            {
                return _crypto[Method].Invoke(FilePath, isEncrypt);

            }
            catch (KeyNotFoundException e)
            {
                throw e;
            }
        }
    }
}
