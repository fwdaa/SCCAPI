using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.ANSI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������ ����������������� ��������
	///////////////////////////////////////////////////////////////////////////
	public partial class NISTControl : CAPI.GUI.CultureControl
	{
        // �����������
		public NISTControl(PBE.PBEParameters pbeParameters) 
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
        public override string Type { get { return "NIST"; }}
        
		// �������� ����������������� ��������
        public override PBE.PBECulture GetCulture() 
        { 
            string hashOID = null; string hmacOID = null; string cipherOID = null;

            // ������� ������������� ��������� �����������
            if (radioSHA1    .Checked) hashOID = ASN1.ANSI.OID.ssig_sha1; 
            if (radioSHA2_224.Checked) hashOID = ASN1.ANSI.OID.nist_sha2_224; 
            if (radioSHA2_256.Checked) hashOID = ASN1.ANSI.OID.nist_sha2_256; 
            if (radioSHA2_384.Checked) hashOID = ASN1.ANSI.OID.nist_sha2_384; 
            if (radioSHA2_512.Checked) hashOID = ASN1.ANSI.OID.nist_sha2_512; 

            // ������� ������������� ��������� ���������� ������������
            if (radioPBKDF2_HMAC_SHA1    .Checked) hmacOID = ASN1.ANSI.OID.rsa_hmac_sha1; 
            if (radioPBKDF2_HMAC_SHA2_224.Checked) hmacOID = ASN1.ANSI.OID.rsa_hmac_sha2_224; 
            if (radioPBKDF2_HMAC_SHA2_256.Checked) hmacOID = ASN1.ANSI.OID.rsa_hmac_sha2_256;
            if (radioPBKDF2_HMAC_SHA2_384.Checked) hmacOID = ASN1.ANSI.OID.rsa_hmac_sha2_384; 
            if (radioPBKDF2_HMAC_SHA2_512.Checked) hmacOID = ASN1.ANSI.OID.rsa_hmac_sha2_512; 

            // ������� ������������� ��������� ����������
            if (radioAES_128_CBC.Checked) cipherOID = ASN1.ANSI.OID.nist_aes128_cbc; 
            if (radioAES_128_OFB.Checked) cipherOID = ASN1.ANSI.OID.nist_aes128_ofb;
            if (radioAES_128_CFB.Checked) cipherOID = ASN1.ANSI.OID.nist_aes128_cfb;
            if (radioAES_192_CBC.Checked) cipherOID = ASN1.ANSI.OID.nist_aes192_cbc;
            if (radioAES_192_OFB.Checked) cipherOID = ASN1.ANSI.OID.nist_aes192_ofb;
            if (radioAES_192_CFB.Checked) cipherOID = ASN1.ANSI.OID.nist_aes192_cfb;
            if (radioAES_256_CBC.Checked) cipherOID = ASN1.ANSI.OID.nist_aes256_cbc;
            if (radioAES_256_OFB.Checked) cipherOID = ASN1.ANSI.OID.nist_aes256_ofb;
            if (radioAES_256_CFB.Checked) cipherOID = ASN1.ANSI.OID.nist_aes256_cfb;

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
            return new Culture.NIST(pbeParameters, hashOID, hmacOID, cipherOID); 
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
