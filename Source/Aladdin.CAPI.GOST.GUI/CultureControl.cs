using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.GOST.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора криптографической культуры
	///////////////////////////////////////////////////////////////////////////
	public partial class CultureControl : CAPI.GUI.CultureControl
	{
        // конструктор
		public CultureControl(PBE.PBEParameters pbeParameters) 
        { 
            InitializeComponent(); 

            // указать начальные значения
            textBoxSaltLengthPBMAC.Text = pbeParameters.PBMSaltLength.ToString(); 
            textBoxIterationsPBMAC.Text = pbeParameters.PBMIterations.ToString(); 
            textBoxSaltLengthPBE  .Text = pbeParameters.PBESaltLength.ToString(); 
            textBoxIterationsPBE  .Text = pbeParameters.PBEIterations.ToString(); 
        }
 		///////////////////////////////////////////////////////////////////////
		// События 
		///////////////////////////////////////////////////////////////////////
		private void OnLoad(object sender, EventArgs e) {}

        // тип криптографической культуры
        public override string Type { get { return "GOST"; }}
        
		// получить криптографическую культуру
        public override PBE.PBECulture GetCulture() 
        { 
            string hashOID = null; string hmacOID = null; string encryptionOID = null;

            // указать идентификатор алгоритма хэширования
            if (radioGOSTR3411_1994    .Checked) hashOID = ASN1.GOST.OID.gostR3411_94; 
            if (radioGOSTR3411_2012_256.Checked) hashOID = ASN1.GOST.OID.gostR3411_2012_256; 
            if (radioGOSTR3411_2012_512.Checked) hashOID = ASN1.GOST.OID.gostR3411_2012_512; 

            // указать идентификатор алгоритма вычисления имитовставки
            if (radioPBKDF2_HMAC_GOSTR3411_1994    .Checked) hmacOID = ASN1.GOST.OID.gostR3411_94_HMAC; 
            if (radioPBKDF2_HMAC_GOSTR3411_2012_256.Checked) hmacOID = ASN1.GOST.OID.gostR3411_2012_HMAC_256; 
            if (radioPBKDF2_HMAC_GOSTR3411_2012_512.Checked) hmacOID = ASN1.GOST.OID.gostR3411_2012_HMAC_512;

            // указать идентификатор алгоритма шифрования
            if (radioGOST28147_A.Checked) encryptionOID = ASN1.GOST.OID.encrypts_A; 
            if (radioGOST28147_B.Checked) encryptionOID = ASN1.GOST.OID.encrypts_B;
            if (radioGOST28147_C.Checked) encryptionOID = ASN1.GOST.OID.encrypts_C;
            if (radioGOST28147_D.Checked) encryptionOID = ASN1.GOST.OID.encrypts_D;
            if (radioMagma      .Checked) encryptionOID = ASN1.GOST.OID.gostR3412_64_ctr_acpkm;
            if (radioKuznyechik .Checked) encryptionOID = ASN1.GOST.OID.gostR3412_128_ctr_acpkm;

            // прочитать значения параметров
            int pbmSaltLength = Int32.Parse(textBoxSaltLengthPBMAC.Text); 
            int pbmIterations = Int32.Parse(textBoxIterationsPBMAC.Text); 
            int pbeSaltLength = Int32.Parse(textBoxSaltLengthPBE  .Text); 
            int pbeIterations = Int32.Parse(textBoxIterationsPBE  .Text); 

            // объединить параметры
            PBE.PBEParameters pbeParameters = new PBE.PBEParameters(
                pbmSaltLength, pbmIterations, pbeSaltLength, pbeIterations
            ); 
            // создать криптографическую культуру
            return new Culture(pbeParameters, hashOID, hmacOID, encryptionOID); 
        }
        private void OnValidating(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // преобразовать тип элемента
            TextBox textBox = (TextBox)sender; int value = 0; 

            // выполнить проверку корректности ввода
            bool fOK = Int32.TryParse(textBox.Text, out value); 

            // проверить корректность данных
            e.Cancel = (!fOK || value <= 0); if (e.Cancel) textBox.Focus();
        }
	}
}
