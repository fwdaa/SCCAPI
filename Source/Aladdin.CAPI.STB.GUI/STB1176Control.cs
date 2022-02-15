using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.STB.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// ������ ������ ����������������� ��������
	///////////////////////////////////////////////////////////////////////////
	public partial class STB1176Control : CAPI.GUI.CultureControl
	{
        // �����������
		public STB1176Control(PBE.PBEParameters pbeParameters) 
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
            string hashOID = null; string hashMacOID = null; string cipherOID = null;

            // ������� ������������� ��������� �����������
            if (radioSTB11761_0 .Checked) hashOID = ASN1.STB.OID.stb11761_hash0; 
            if (radioSTB11761_A .Checked) hashOID = ASN1.STB.OID.stb11761_hashA; 
            if (radioSTB11761_4E.Checked) hashOID = ASN1.STB.OID.stb11761_hash4E; 

            // ������� ������������� ��������� ���������� ������������
            if (radioPBKDF2_HMAC_STB11761_0 .Checked) hashMacOID = ASN1.STB.OID.stb11761_hash0; 
            if (radioPBKDF2_HMAC_STB11761_A .Checked) hashMacOID = ASN1.STB.OID.stb11761_hashA; 
            if (radioPBKDF2_HMAC_STB11761_4E.Checked) hashMacOID = ASN1.STB.OID.stb11761_hash4E;

            // ������� ������������� ��������� ����������
            if (radioGOST28147_CFB.Checked) cipherOID = ASN1.STB.OID.gost28147_cfb; 
            if (radioGOST28147_CTR.Checked) cipherOID = ASN1.STB.OID.gost28147_ctr;

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
            return new Culture.STB1176(pbeParameters, hashOID, hashMacOID, cipherOID); 
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
