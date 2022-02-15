using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.STB.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора криптографической культуры
	///////////////////////////////////////////////////////////////////////////
	public partial class STB1176Control : CAPI.GUI.CultureControl
	{
        // конструктор
		public STB1176Control(PBE.PBEParameters pbeParameters) 
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
        public override string Type { get { return "STB 1176"; }}
        
		// получить криптографическую культуру
        public override PBE.PBECulture GetCulture() 
        { 
            string hashOID = null; string hashMacOID = null; string cipherOID = null;

            // указать идентификатор алгоритма хэширования
            if (radioSTB11761_0 .Checked) hashOID = ASN1.STB.OID.stb11761_hash0; 
            if (radioSTB11761_A .Checked) hashOID = ASN1.STB.OID.stb11761_hashA; 
            if (radioSTB11761_4E.Checked) hashOID = ASN1.STB.OID.stb11761_hash4E; 

            // указать идентификатор алгоритма вычисления имитовставки
            if (radioPBKDF2_HMAC_STB11761_0 .Checked) hashMacOID = ASN1.STB.OID.stb11761_hash0; 
            if (radioPBKDF2_HMAC_STB11761_A .Checked) hashMacOID = ASN1.STB.OID.stb11761_hashA; 
            if (radioPBKDF2_HMAC_STB11761_4E.Checked) hashMacOID = ASN1.STB.OID.stb11761_hash4E;

            // указать идентификатор алгоритма шифрования
            if (radioGOST28147_CFB.Checked) cipherOID = ASN1.STB.OID.gost28147_cfb; 
            if (radioGOST28147_CTR.Checked) cipherOID = ASN1.STB.OID.gost28147_ctr;

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
            return new Culture.STB1176(pbeParameters, hashOID, hashMacOID, cipherOID); 
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
