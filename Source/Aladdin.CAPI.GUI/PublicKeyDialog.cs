using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора ключа
	///////////////////////////////////////////////////////////////////////////
	public partial class PublicKeyDialog : Form
	{
        private CryptoEnvironment   environment;    // криптографическая среда 
        private IPublicKey          publicKey;      // открытый ключ

		public PublicKeyDialog(CryptoEnvironment environment, IPublicKey publicKey) 
        { 
            // сохранить переданные параметры
            InitializeComponent(); this.environment = environment; this.publicKey = publicKey; 
		}
		public PublicKeyDialog() { InitializeComponent(); }

        private void OnLoad(object sender, EventArgs e)
        {
            // определить имя ключа
            string keyName = environment.GetKeyName(publicKey.KeyOID);  

            // указать имя ключа
            textBoxOID.Text = String.Format("{0} ({1})", keyName, publicKey.KeyOID);
            try { 
                // закодировать открытый ключ
                ASN1.ISO.PKIX.SubjectPublicKeyInfo publicKeyInfo = publicKey.Encoded; 

                // получить закодированное содержимое
                byte[] encoded = publicKeyInfo.Encoded; 

                // указать содержимое ключа
                textBoxBase64.Text = Base64.GetEncoder().EncodeToString(encoded); 

                // указать содержимое ключа
                textBoxValue.Text = Arrays.ToHexString(encoded); 
            }
            // обработать возможное исключение
            catch (Exception) { textBoxValue.Text = textBoxBase64.Text = "N/A"; }
        }
	}
}
