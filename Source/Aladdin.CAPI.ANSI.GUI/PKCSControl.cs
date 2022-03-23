using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.ANSI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������ ����������������� ��������
	///////////////////////////////////////////////////////////////////////////
	public partial class PKCSControl : CAPI.GUI.CultureControl
	{
        // �����������
		public PKCSControl(PBE.PBEParameters pbeParameters) 
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
        public override string Type { get { return "PKCS"; }}
        
		// �������� ����������������� ��������
        public override PBE.PBECulture GetCulture() 
        { 
            string hashOID = null; string cipherOIDV = null;

            // ������� ������������� ��������� �����������
            if (radioMD2 .Checked) hashOID = ASN1.ANSI.OID.rsa_md2; 
            if (radioMD5 .Checked) hashOID = ASN1.ANSI.OID.rsa_md5; 
            if (radioSHA1.Checked) hashOID = ASN1.ANSI.OID.ssig_sha1; 

            // ������� ������������� ��������� ����������
            if (radioMD2_DES_CBC      .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS5 .OID.pbe_md2_des_cbc; 
            if (radioMD5_DES_CBC      .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS5 .OID.pbe_md5_des_cbc;
            if (radioMD2_RC2_64_CBC   .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS5 .OID.pbe_md2_rc2_64_cbc;
            if (radioMD5_RC2_64_CBC   .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS5 .OID.pbe_md5_rc2_64_cbc;
            if (radioSHA1_DES_CBC     .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS5 .OID.pbe_sha1_des_cbc;
            if (radioSHA1_RC2_64_CBC  .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS5 .OID.pbe_sha1_rc2_64_cbc;
            if (radioSHA1_RC4_128     .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_128;
            if (radioSHA1_RC4_40      .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc4_40;
            if (radioSHA1_RC2_128_CBC .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_128_cbc;
            if (radioSHA1_RC2_40_CBC  .Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_rc2_40_cbc;
            if (radioSHA1_TDES_192_CBC.Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_192_cbc;
            if (radioSHA1_TDES_128_CBC.Checked) cipherOIDV = ASN1.ISO.PKCS.PKCS12.OID.pbe_sha1_tdes_128_cbc;

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
            return new Culture.PKCS(pbeParameters, hashOID, cipherOIDV); 
        }
        private void OnCheckedChanged(object sender, EventArgs e)
        {
            // ������������� ��� ��������
            RadioButton radioButton = (RadioButton)sender; if (!radioButton.Checked) return; 
            
            // � ����������� �� ����������� ��������
            if (radioButton.Name == "radioMD2_DES_CBC"    || radioButton.Name == "radioMD5_DES_CBC"     || 
                radioButton.Name == "radioMD2_RC2_64_CBC" || radioButton.Name == "radioMD5_RC2_64_CBC"  || 
                radioButton.Name == "radioSHA1_DES_CBC"   || radioButton.Name == "radioSHA1_RC2_64_CBC")
            {
                // �������� ����� ��������� ������ ������
                if (radioSHA1_RC4_128     .Checked) radioSHA1_RC4_128     .Checked = false; 
                if (radioSHA1_RC4_40      .Checked) radioSHA1_RC4_40      .Checked = false; 
                if (radioSHA1_RC2_128_CBC .Checked) radioSHA1_RC2_128_CBC .Checked = false; 
                if (radioSHA1_RC2_40_CBC  .Checked) radioSHA1_RC2_40_CBC  .Checked = false; 
                if (radioSHA1_TDES_192_CBC.Checked) radioSHA1_TDES_192_CBC.Checked = false; 
                if (radioSHA1_TDES_128_CBC.Checked) radioSHA1_TDES_128_CBC.Checked = false; 
            }
            // � ����������� �� ����������� ��������
            if (radioButton.Name == "radioSHA1_RC4_128"      || radioButton.Name == "radioSHA1_RC4_40"      || 
                radioButton.Name == "radioSHA1_RC2_128_CBC"  || radioButton.Name == "radioSHA1_RC2_40_CBC"  || 
                radioButton.Name == "radioSHA1_TDES_192_CBC" || radioButton.Name == "radioSHA1_TDES_128_CBC")
            {
                // �������� ����� ��������� ������ ������
                if (radioMD2_DES_CBC    .Checked) radioMD2_DES_CBC    .Checked = false; 
                if (radioMD5_DES_CBC    .Checked) radioMD5_DES_CBC    .Checked = false; 
                if (radioMD2_RC2_64_CBC .Checked) radioMD2_RC2_64_CBC .Checked = false; 
                if (radioMD5_RC2_64_CBC .Checked) radioMD5_RC2_64_CBC .Checked = false; 
                if (radioSHA1_DES_CBC   .Checked) radioSHA1_DES_CBC   .Checked = false; 
                if (radioSHA1_RC2_64_CBC.Checked) radioSHA1_RC2_64_CBC.Checked = false; 
            }
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
