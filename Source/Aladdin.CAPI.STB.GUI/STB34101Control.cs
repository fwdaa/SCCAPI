using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.STB.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог выбора криптографической культуры
	///////////////////////////////////////////////////////////////////////////
	public partial class STB34101Control : CAPI.GUI.CultureControl
	{
        // конструктор
		public STB34101Control(PBE.PBEParameters pbeParameters) 
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
            string hashOID = null; string hmacOID = null; string cipherOID = null;

            // указать идентификатор алгоритма хэширования
            if (radioSTB34101.Checked) hashOID = ASN1.STB.OID.stb34101_belt_hash; 

            // указать идентификатор алгоритма вычисления имитовставки
            if (radioPBKDF2_HMAC_STB34101.Checked) hmacOID = ASN1.STB.OID.stb34101_hmac_hbelt; 

            // указать идентификатор алгоритма шифрования
            if (radioSTB34101_CBC_128.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cbc_128; 
            if (radioSTB34101_CFB_128.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cfb_128; 
            if (radioSTB34101_CTR_128.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_ctr_128; 
            if (radioSTB34101_CBC_192.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cbc_192; 
            if (radioSTB34101_CFB_192.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cfb_192; 
            if (radioSTB34101_CTR_192.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_ctr_192; 
            if (radioSTB34101_CBC_256.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cbc_256; 
            if (radioSTB34101_CFB_256.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cfb_256; 
            if (radioSTB34101_CTR_256.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_ctr_256; 

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
            return new Culture.STB34101(pbeParameters, hashOID, hmacOID, cipherOID); 
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
