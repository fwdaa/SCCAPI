namespace Aladdin.CAPI.KZ.GUI
{
	public partial class CultureControl
	{
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.Container components = null;

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (components != null)
				{
					components.Dispose();
				}
			}
			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CultureControl));
            this.TitleLabel = new System.Windows.Forms.Label();
            this.groupBoxPBES2Cipher = new System.Windows.Forms.GroupBox();
            this.radioGOST28147_OFB = new System.Windows.Forms.RadioButton();
            this.radioGOST28147_CTR = new System.Windows.Forms.RadioButton();
            this.radioGOST28147_CFB = new System.Windows.Forms.RadioButton();
            this.radioGOST28147_CBC = new System.Windows.Forms.RadioButton();
            this.groupBoxPBES2KDF = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBE = new System.Windows.Forms.Label();
            this.radioPBKDF2_HMAC_GOSTR3411_1994_CP = new System.Windows.Forms.RadioButton();
            this.radioPBKDF2_HMAC_GOST34311_1995_T = new System.Windows.Forms.RadioButton();
            this.labelSaltLengthPBE = new System.Windows.Forms.Label();
            this.textBoxIterationsPBE = new System.Windows.Forms.TextBox();
            this.textBoxSaltLengthPBE = new System.Windows.Forms.TextBox();
            this.groupBoxPBE = new System.Windows.Forms.GroupBox();
            this.groupBoxPBMAC = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBMAC = new System.Windows.Forms.Label();
            this.textBoxIterationsPBMAC = new System.Windows.Forms.TextBox();
            this.labelSaltLengthPBMAC = new System.Windows.Forms.Label();
            this.textBoxSaltLengthPBMAC = new System.Windows.Forms.TextBox();
            this.groupBoxHash = new System.Windows.Forms.GroupBox();
            this.radioGOSTR3411_1994_CP = new System.Windows.Forms.RadioButton();
            this.radioGOST34311_1995_T = new System.Windows.Forms.RadioButton();
            this.groupBoxPBES2Cipher.SuspendLayout();
            this.groupBoxPBES2KDF.SuspendLayout();
            this.groupBoxPBE.SuspendLayout();
            this.groupBoxPBMAC.SuspendLayout();
            this.groupBoxHash.SuspendLayout();
            this.SuspendLayout();
            // 
            // TitleLabel
            // 
            resources.ApplyResources(this.TitleLabel, "TitleLabel");
            this.TitleLabel.BackColor = System.Drawing.Color.Transparent;
            this.TitleLabel.Name = "TitleLabel";
            // 
            // groupBoxPBES2Cipher
            // 
            resources.ApplyResources(this.groupBoxPBES2Cipher, "groupBoxPBES2Cipher");
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_OFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_CTR);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_CFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_CBC);
            this.groupBoxPBES2Cipher.Name = "groupBoxPBES2Cipher";
            this.groupBoxPBES2Cipher.TabStop = false;
            // 
            // radioGOST28147_OFB
            // 
            resources.ApplyResources(this.radioGOST28147_OFB, "radioGOST28147_OFB");
            this.radioGOST28147_OFB.Name = "radioGOST28147_OFB";
            this.radioGOST28147_OFB.UseVisualStyleBackColor = true;
            // 
            // radioGOST28147_CTR
            // 
            resources.ApplyResources(this.radioGOST28147_CTR, "radioGOST28147_CTR");
            this.radioGOST28147_CTR.Name = "radioGOST28147_CTR";
            this.radioGOST28147_CTR.UseVisualStyleBackColor = true;
            // 
            // radioGOST28147_CFB
            // 
            resources.ApplyResources(this.radioGOST28147_CFB, "radioGOST28147_CFB");
            this.radioGOST28147_CFB.Checked = true;
            this.radioGOST28147_CFB.Name = "radioGOST28147_CFB";
            this.radioGOST28147_CFB.TabStop = true;
            this.radioGOST28147_CFB.UseVisualStyleBackColor = true;
            // 
            // radioGOST28147_CBC
            // 
            resources.ApplyResources(this.radioGOST28147_CBC, "radioGOST28147_CBC");
            this.radioGOST28147_CBC.Name = "radioGOST28147_CBC";
            this.radioGOST28147_CBC.UseVisualStyleBackColor = true;
            // 
            // groupBoxPBES2KDF
            // 
            resources.ApplyResources(this.groupBoxPBES2KDF, "groupBoxPBES2KDF");
            this.groupBoxPBES2KDF.Controls.Add(this.labelIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_GOSTR3411_1994_CP);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_GOST34311_1995_T);
            this.groupBoxPBES2KDF.Controls.Add(this.labelSaltLengthPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxSaltLengthPBE);
            this.groupBoxPBES2KDF.Name = "groupBoxPBES2KDF";
            this.groupBoxPBES2KDF.TabStop = false;
            // 
            // labelIterationsPBE
            // 
            resources.ApplyResources(this.labelIterationsPBE, "labelIterationsPBE");
            this.labelIterationsPBE.Name = "labelIterationsPBE";
            // 
            // radioPBKDF2_HMAC_GOSTR3411_1994_CP
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_GOSTR3411_1994_CP, "radioPBKDF2_HMAC_GOSTR3411_1994_CP");
            this.radioPBKDF2_HMAC_GOSTR3411_1994_CP.Name = "radioPBKDF2_HMAC_GOSTR3411_1994_CP";
            this.radioPBKDF2_HMAC_GOSTR3411_1994_CP.TabStop = true;
            this.radioPBKDF2_HMAC_GOSTR3411_1994_CP.UseVisualStyleBackColor = true;
            // 
            // radioPBKDF2_HMAC_GOST34311_1995_T
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_GOST34311_1995_T, "radioPBKDF2_HMAC_GOST34311_1995_T");
            this.radioPBKDF2_HMAC_GOST34311_1995_T.Checked = true;
            this.radioPBKDF2_HMAC_GOST34311_1995_T.Name = "radioPBKDF2_HMAC_GOST34311_1995_T";
            this.radioPBKDF2_HMAC_GOST34311_1995_T.TabStop = true;
            this.radioPBKDF2_HMAC_GOST34311_1995_T.UseVisualStyleBackColor = true;
            // 
            // labelSaltLengthPBE
            // 
            resources.ApplyResources(this.labelSaltLengthPBE, "labelSaltLengthPBE");
            this.labelSaltLengthPBE.Name = "labelSaltLengthPBE";
            // 
            // textBoxIterationsPBE
            // 
            resources.ApplyResources(this.textBoxIterationsPBE, "textBoxIterationsPBE");
            this.textBoxIterationsPBE.Name = "textBoxIterationsPBE";
            this.textBoxIterationsPBE.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // textBoxSaltLengthPBE
            // 
            resources.ApplyResources(this.textBoxSaltLengthPBE, "textBoxSaltLengthPBE");
            this.textBoxSaltLengthPBE.Name = "textBoxSaltLengthPBE";
            this.textBoxSaltLengthPBE.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // groupBoxPBE
            // 
            resources.ApplyResources(this.groupBoxPBE, "groupBoxPBE");
            this.groupBoxPBE.Controls.Add(this.groupBoxPBES2Cipher);
            this.groupBoxPBE.Controls.Add(this.groupBoxPBES2KDF);
            this.groupBoxPBE.Name = "groupBoxPBE";
            this.groupBoxPBE.TabStop = false;
            // 
            // groupBoxPBMAC
            // 
            resources.ApplyResources(this.groupBoxPBMAC, "groupBoxPBMAC");
            this.groupBoxPBMAC.Controls.Add(this.labelIterationsPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.textBoxIterationsPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.labelSaltLengthPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.textBoxSaltLengthPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.groupBoxHash);
            this.groupBoxPBMAC.Name = "groupBoxPBMAC";
            this.groupBoxPBMAC.TabStop = false;
            // 
            // labelIterationsPBMAC
            // 
            resources.ApplyResources(this.labelIterationsPBMAC, "labelIterationsPBMAC");
            this.labelIterationsPBMAC.Name = "labelIterationsPBMAC";
            // 
            // textBoxIterationsPBMAC
            // 
            resources.ApplyResources(this.textBoxIterationsPBMAC, "textBoxIterationsPBMAC");
            this.textBoxIterationsPBMAC.Name = "textBoxIterationsPBMAC";
            this.textBoxIterationsPBMAC.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // labelSaltLengthPBMAC
            // 
            resources.ApplyResources(this.labelSaltLengthPBMAC, "labelSaltLengthPBMAC");
            this.labelSaltLengthPBMAC.Name = "labelSaltLengthPBMAC";
            // 
            // textBoxSaltLengthPBMAC
            // 
            resources.ApplyResources(this.textBoxSaltLengthPBMAC, "textBoxSaltLengthPBMAC");
            this.textBoxSaltLengthPBMAC.Name = "textBoxSaltLengthPBMAC";
            this.textBoxSaltLengthPBMAC.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // groupBoxHash
            // 
            resources.ApplyResources(this.groupBoxHash, "groupBoxHash");
            this.groupBoxHash.Controls.Add(this.radioGOSTR3411_1994_CP);
            this.groupBoxHash.Controls.Add(this.radioGOST34311_1995_T);
            this.groupBoxHash.Name = "groupBoxHash";
            this.groupBoxHash.TabStop = false;
            // 
            // radioGOSTR3411_1994_CP
            // 
            resources.ApplyResources(this.radioGOSTR3411_1994_CP, "radioGOSTR3411_1994_CP");
            this.radioGOSTR3411_1994_CP.Name = "radioGOSTR3411_1994_CP";
            this.radioGOSTR3411_1994_CP.TabStop = true;
            this.radioGOSTR3411_1994_CP.UseVisualStyleBackColor = true;
            // 
            // radioGOST34311_1995_T
            // 
            resources.ApplyResources(this.radioGOST34311_1995_T, "radioGOST34311_1995_T");
            this.radioGOST34311_1995_T.Checked = true;
            this.radioGOST34311_1995_T.Name = "radioGOST34311_1995_T";
            this.radioGOST34311_1995_T.TabStop = true;
            this.radioGOST34311_1995_T.UseVisualStyleBackColor = true;
            // 
            // CultureControl
            // 
            resources.ApplyResources(this, "$this");
            this.Controls.Add(this.groupBoxPBMAC);
            this.Controls.Add(this.groupBoxPBE);
            this.Name = "CultureControl";
            this.Load += new System.EventHandler(this.OnLoad);
            this.groupBoxPBES2Cipher.ResumeLayout(false);
            this.groupBoxPBES2Cipher.PerformLayout();
            this.groupBoxPBES2KDF.ResumeLayout(false);
            this.groupBoxPBES2KDF.PerformLayout();
            this.groupBoxPBE.ResumeLayout(false);
            this.groupBoxPBMAC.ResumeLayout(false);
            this.groupBoxPBMAC.PerformLayout();
            this.groupBoxHash.ResumeLayout(false);
            this.groupBoxHash.PerformLayout();
            this.ResumeLayout(false);

		}
		#endregion

        private System.Windows.Forms.Label TitleLabel;
        private System.Windows.Forms.GroupBox groupBoxPBES2Cipher;
        private System.Windows.Forms.RadioButton radioGOST28147_CBC;
        private System.Windows.Forms.GroupBox groupBoxPBES2KDF;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_GOST34311_1995_T;
        private System.Windows.Forms.GroupBox groupBoxPBE;
        private System.Windows.Forms.RadioButton radioGOST28147_CTR;
        private System.Windows.Forms.RadioButton radioGOST28147_CFB;
        private System.Windows.Forms.Label labelIterationsPBE;
        private System.Windows.Forms.TextBox textBoxIterationsPBE;
        private System.Windows.Forms.Label labelSaltLengthPBE;
        private System.Windows.Forms.TextBox textBoxSaltLengthPBE;
        private System.Windows.Forms.GroupBox groupBoxPBMAC;
        private System.Windows.Forms.Label labelIterationsPBMAC;
        private System.Windows.Forms.TextBox textBoxIterationsPBMAC;
        private System.Windows.Forms.Label labelSaltLengthPBMAC;
        private System.Windows.Forms.TextBox textBoxSaltLengthPBMAC;
        private System.Windows.Forms.GroupBox groupBoxHash;
        private System.Windows.Forms.RadioButton radioGOST34311_1995_T;
        private System.Windows.Forms.RadioButton radioGOSTR3411_1994_CP;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_GOSTR3411_1994_CP;
        private System.Windows.Forms.RadioButton radioGOST28147_OFB;

	}
}
