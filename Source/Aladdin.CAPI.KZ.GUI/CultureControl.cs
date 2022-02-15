using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.KZ.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������ ����������������� ��������
	///////////////////////////////////////////////////////////////////////////
	public partial class CultureControl : CAPI.GUI.CultureControl
	{
        // �����������
		public CultureControl(PBE.PBEParameters pbeParameters) 
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
        public override string Type { get { return "KZ"; }}
        
		// �������� ����������������� ��������
        public override PBE.PBECulture GetCulture() 
        { 
            string hashOID = null; string hmacOID = null; string cipherOID = null;

            // ������� ������������� ��������� �����������
            if (radioGOST34311_1995_T .Checked) hashOID = ASN1.KZ.OID.gamma_gost34311_95; 
            if (radioGOSTR3411_1994_CP.Checked) hashOID = ASN1.GOST.OID.gostR3411_94; 

            // ������� ������������� ��������� ���������� ������������
            if (radioPBKDF2_HMAC_GOST34311_1995_T .Checked) hmacOID = ASN1.KZ.OID.gamma_hmac_gost34311_95_t; 
            if (radioPBKDF2_HMAC_GOSTR3411_1994_CP.Checked) hmacOID = ASN1.KZ.OID.gamma_hmac_gostR3411_94_cp; 

            // ������� ������������� ��������� ����������
            if (radioGOST28147_CBC.Checked) cipherOID = ASN1.KZ.OID.gamma_cipher_gost_cbc; 
            if (radioGOST28147_CFB.Checked) cipherOID = ASN1.KZ.OID.gamma_cipher_gost;
            if (radioGOST28147_CTR.Checked) cipherOID = ASN1.KZ.OID.gamma_cipher_gost_cnt;
            if (radioGOST28147_OFB.Checked) cipherOID = ASN1.KZ.OID.gamma_cipher_gost_ofb;

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
            return new Culture(pbeParameters, hashOID, hmacOID, cipherOID); 
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
