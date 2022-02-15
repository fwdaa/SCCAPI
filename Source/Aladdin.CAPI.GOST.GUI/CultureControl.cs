using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.GOST.GUI
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
        public override string Type { get { return "GOST"; }}
        
		// �������� ����������������� ��������
        public override PBE.PBECulture GetCulture() 
        { 
            string hashOID = null; string hmacOID = null; string encryptionOID = null;

            // ������� ������������� ��������� �����������
            if (radioGOSTR3411_1994    .Checked) hashOID = ASN1.GOST.OID.gostR3411_94; 
            if (radioGOSTR3411_2012_256.Checked) hashOID = ASN1.GOST.OID.gostR3411_2012_256; 
            if (radioGOSTR3411_2012_512.Checked) hashOID = ASN1.GOST.OID.gostR3411_2012_512; 

            // ������� ������������� ��������� ���������� ������������
            if (radioPBKDF2_HMAC_GOSTR3411_1994    .Checked) hmacOID = ASN1.GOST.OID.gostR3411_94_HMAC; 
            if (radioPBKDF2_HMAC_GOSTR3411_2012_256.Checked) hmacOID = ASN1.GOST.OID.gostR3411_2012_HMAC_256; 
            if (radioPBKDF2_HMAC_GOSTR3411_2012_512.Checked) hmacOID = ASN1.GOST.OID.gostR3411_2012_HMAC_512;

            // ������� ������������� ��������� ����������
            if (radioGOST28147_A.Checked) encryptionOID = ASN1.GOST.OID.encrypts_A; 
            if (radioGOST28147_B.Checked) encryptionOID = ASN1.GOST.OID.encrypts_B;
            if (radioGOST28147_C.Checked) encryptionOID = ASN1.GOST.OID.encrypts_C;
            if (radioGOST28147_D.Checked) encryptionOID = ASN1.GOST.OID.encrypts_D;
            if (radioMagma      .Checked) encryptionOID = ASN1.GOST.OID.gostR3412_64_ctr_acpkm;
            if (radioKuznyechik .Checked) encryptionOID = ASN1.GOST.OID.gostR3412_128_ctr_acpkm;

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
            return new Culture(pbeParameters, hashOID, hmacOID, encryptionOID); 
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
