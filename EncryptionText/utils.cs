using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionText
{
    public class  Utils
    {
        public static byte[] genKeys(string key)
        {
            var data = Encoding.UTF8.GetBytes(key);
            var _In = new byte[16] { 207, 63, 204, 71, 183, 48, 11, 223, 51, 176, 5, 227, 20, 237, 247, 218 };
            for (int i = 0; i < data.Length; i++)
            {
                _In[i % 16] = (byte)(_In[i % 16] ^ data[i]);
            }
            return _In;
        }

        public static byte[] genIVs(string key)
        {
            var data = Encoding.UTF8.GetBytes(key);
            var _In = new byte[16] { 10, 82, 199, 159, 156, 212, 97, 193, 222, 17, 140, 253, 216, 178, 149, 141 };
            for (int i = 0; i < data.Length; i++)
            {
                _In[i % 16] = (byte)(_In[i % 16] ^ data[i]);
            }
            _In.Reverse();
            return _In;

        }
    }
}
