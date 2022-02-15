using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.STB.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������ ����������������� ��������
	///////////////////////////////////////////////////////////////////////////
	public partial class STB34101Control : CAPI.GUI.CultureControl
	{
        // �����������
		public STB34101Control(PBE.PBEParameters pbeParameters) 
        { 
            InitializeComponent(); 

            // ������� ��������� ��������
            textBoxSaltLengthPBMAC.Text = pbeParameters.PBMSaltLength.ToString(); 
            textBoxIterationsPBMAC.Text = pbeParameters.PBMIterations.ToString(); 
            textBoxSaltLengthPBE  .Text = pbeParameters.PBESaltLength.ToString(); 
            textBoxIterationsPBE  .Text = pbeParameters.PBEIterations.ToString(); 
        }
 		///////////////////////////////////////////////////////////////////////
		// ������� 
		///////////////////////////////////////////////////////////////////////
		private void OnLoad(object sender, EventArgs e) {}

        // ��� ����������������� ��������
        public override string Type { get { return "STB 1176"; }}
        
		// �������� ����������������� ��������
        public override PBE.PBECulture GetCulture() 
        { 
            string hashOID = null; string hmacOID = null; string cipherOID = null;

            // ������� ������������� ��������� �����������
            if (radioSTB34101.Checked) hashOID = ASN1.STB.OID.stb34101_belt_hash; 

            // ������� ������������� ��������� ���������� ������������
            if (radioPBKDF2_HMAC_STB34101.Checked) hmacOID = ASN1.STB.OID.stb34101_hmac_hbelt; 

            // ������� ������������� ��������� ����������
            if (radioSTB34101_CBC_128.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cbc_128; 
            if (radioSTB34101_CFB_128.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cfb_128; 
            if (radioSTB34101_CTR_128.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_ctr_128; 
            if (radioSTB34101_CBC_192.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cbc_192; 
            if (radioSTB34101_CFB_192.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cfb_192; 
            if (radioSTB34101_CTR_192.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_ctr_192; 
            if (radioSTB34101_CBC_256.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cbc_256; 
            if (radioSTB34101_CFB_256.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_cfb_256; 
            if (radioSTB34101_CTR_256.Checked) cipherOID = ASN1.STB.OID.stb34101_belt_ctr_256; 

            // ��������� �������� ����������
            int pbmSaltLength = Int32.Parse(textBoxSaltLengthPBMAC.Text); 
            int pbmIterations = Int32.Parse(textBoxIterationsPBMAC.Text); 
            int pbeSaltLength = Int32.Parse(textBoxSaltLengthPBE  .Text); 
            int pbeIterations = Int32.Parse(textBoxIterationsPBE  .Text); 

            // ���������� ���������
            PBE.PBEParameters pbeParameters = new PBE.PBEParameters(
                pbmSaltLength, pbmIterations, pbeSaltLength, pbeIterations
            ); 
            // ������� ����������������� ��������
            return new Culture.STB34101(pbeParameters, hashOID, hmacOID, cipherOID); 
        }
        private void OnValidating(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // ������������� ��� ��������
            TextBox textBox = (TextBox)sender; int value = 0; 

            // ��������� �������� ������������ �����
            bool fOK = Int32.TryParse(textBox.Text, out value); 

            // ��������� ������������ ������
            e.Cancel = (!fOK || value <= 0); if (e.Cancel) textBox.Focus();
        }
	}
}
