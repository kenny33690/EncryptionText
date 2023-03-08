using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;
using EncryptionText.Crypto;

namespace EncryptionText
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }


        private void button1_Click(object sender, EventArgs e)
        {

            var key = tbKey.Text;
            openFileDialog1.Title = "选择你要加密的文件";
            if (openFileDialog1.ShowDialog() != DialogResult.OK) { return; }            
            
            var fileName = openFileDialog1.FileName;
            
            if (fileName.Equals("")) return;
            if (fileName.EndsWith(".enc"))
            {
                var aes = CryptoFactory.CreateCrypto(fileName, false);
                aes.Decrypt(key);

                return;
            }

            var toAes = (RSACrypto)CryptoFactory.CreateCrypto(fileName,true,"RSA");
            toAes.Encrypt(key);
            toAes.Save();


#if false
            var parDir = Path.GetDirectoryName(fileName);
            var encFile = Path.Combine(parDir, Path.GetFileName(fileName) + ".enc");

            var aes = Aes.Create();
            aes.Key = genKeys(key);
            var encTrans = aes.CreateEncryptor();
            ToBase64Transform toBase64Transform = new ToBase64Transform();

            var fs1 = new FileStream(fileName,FileMode.Open);
            var fs2 = new FileStream(encFile, FileMode.Create);
            var br = new BinaryReader(fs1);
            //var bw = new BinaryWriter(fs2);
            byte[] buffer = new byte[1024];
            byte[] out_buffer = new byte[1024];
            List<string> baseString = new List<string>((int)(new FileInfo(fileName)).Length / 1024);

            while (br.Read(buffer, 0, buffer.Length)>0)
            {
                encTrans.TransformBlock(buffer, 0, buffer.Length, out_buffer, 0);
                //toBase64Transform.TransformBlock(out_buffer, 0, out_buffer.Length, buffer, 0);
                //bw.Write(out_buffer);
                baseString.Add(Convert.ToBase64String(out_buffer));
                
            }
            //bw.Flush();
            br.Close();
            //bw.Close();
            fs1.Close();
            //fs2.Close();
#endif

        }

        private void Form1_Load(object sender, EventArgs e)
        {
            //Console.WriteLine(AES.Method);
        }
    }
}
