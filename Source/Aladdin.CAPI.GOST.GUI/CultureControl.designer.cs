namespace Aladdin.CAPI.GOST.GUI
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
            this.radioKuznyechik = new System.Windows.Forms.RadioButton();
            this.radioMagma = new System.Windows.Forms.RadioButton();
            this.radioGOST28147_C = new System.Windows.Forms.RadioButton();
            this.radioGOST28147_B = new System.Windows.Forms.RadioButton();
            this.radioGOST28147_D = new System.Windows.Forms.RadioButton();
            this.radioGOST28147_A = new System.Windows.Forms.RadioButton();
            this.groupBoxPBES2KDF = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBE = new System.Windows.Forms.Label();
            this.radioPBKDF2_HMAC_GOSTR3411_2012_256 = new System.Windows.Forms.RadioButton();
            this.radioPBKDF2_HMAC_GOSTR3411_2012_512 = new System.Windows.Forms.RadioButton();
            this.radioPBKDF2_HMAC_GOSTR3411_1994 = new System.Windows.Forms.RadioButton();
            this.textBoxIterationsPBE = new System.Windows.Forms.TextBox();
            this.textBoxSaltLengthPBE = new System.Windows.Forms.TextBox();
            this.labelSaltLengthPBE = new System.Windows.Forms.Label();
            this.groupBoxPBE = new System.Windows.Forms.GroupBox();
            this.groupBoxPBMAC = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBMAC = new System.Windows.Forms.Label();
            this.textBoxIterationsPBMAC = new System.Windows.Forms.TextBox();
            this.labelSaltLengthPBMAC = new System.Windows.Forms.Label();
            this.textBoxSaltLengthPBMAC = new System.Windows.Forms.TextBox();
            this.groupBoxHash = new System.Windows.Forms.GroupBox();
            this.radioGOSTR3411_2012_256 = new System.Windows.Forms.RadioButton();
            this.radioGOSTR3411_2012_512 = new System.Windows.Forms.RadioButton();
            this.radioGOSTR3411_1994 = new System.Windows.Forms.RadioButton();
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
            this.groupBoxPBES2Cipher.Controls.Add(this.radioKuznyechik);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioMagma);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_C);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_B);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_D);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioGOST28147_A);
            this.groupBoxPBES2Cipher.Name = "groupBoxPBES2Cipher";
            this.groupBoxPBES2Cipher.TabStop = false;
            // 
            // radioKuznyechik
            // 
            resources.ApplyResources(this.radioKuznyechik, "radioKuznyechik");
            this.radioKuznyechik.Name = "radioKuznyechik";
            this.radioKuznyechik.UseVisualStyleBackColor = true;
            // 
            // radioMagma
            // 
            resources.ApplyResources(this.radioMagma, "radioMagma");
            this.radioMagma.Name = "radioMagma";
            this.radioMagma.UseVisualStyleBackColor = true;
            // 
            // radioGOST28147_C
            // 
            resources.ApplyResources(this.radioGOST28147_C, "radioGOST28147_C");
            this.radioGOST28147_C.Name = "radioGOST28147_C";
            this.radioGOST28147_C.UseVisualStyleBackColor = true;
            // 
            // radioGOST28147_B
            // 
            resources.ApplyResources(this.radioGOST28147_B, "radioGOST28147_B");
            this.radioGOST28147_B.Name = "radioGOST28147_B";
            this.radioGOST28147_B.UseVisualStyleBackColor = true;
            // 
            // radioGOST28147_D
            // 
            resources.ApplyResources(this.radioGOST28147_D, "radioGOST28147_D");
            this.radioGOST28147_D.Name = "radioGOST28147_D";
            this.radioGOST28147_D.UseVisualStyleBackColor = true;
            // 
            // radioGOST28147_A
            // 
            resources.ApplyResources(this.radioGOST28147_A, "radioGOST28147_A");
            this.radioGOST28147_A.Checked = true;
            this.radioGOST28147_A.Name = "radioGOST28147_A";
            this.radioGOST28147_A.TabStop = true;
            this.radioGOST28147_A.UseVisualStyleBackColor = true;
            // 
            // groupBoxPBES2KDF
            // 
            resources.ApplyResources(this.groupBoxPBES2KDF, "groupBoxPBES2KDF");
            this.groupBoxPBES2KDF.Controls.Add(this.labelIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_GOSTR3411_2012_256);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_GOSTR3411_2012_512);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_GOSTR3411_1994);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxSaltLengthPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.labelSaltLengthPBE);
            this.groupBoxPBES2KDF.Name = "groupBoxPBES2KDF";
            this.groupBoxPBES2KDF.TabStop = false;
            // 
            // labelIterationsPBE
            // 
            resources.ApplyResources(this.labelIterationsPBE, "labelIterationsPBE");
            this.labelIterationsPBE.Name = "labelIterationsPBE";
            // 
            // radioPBKDF2_HMAC_GOSTR3411_2012_256
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_GOSTR3411_2012_256, "radioPBKDF2_HMAC_GOSTR3411_2012_256");
            this.radioPBKDF2_HMAC_GOSTR3411_2012_256.Name = "radioPBKDF2_HMAC_GOSTR3411_2012_256";
            this.radioPBKDF2_HMAC_GOSTR3411_2012_256.TabStop = true;
            this.radioPBKDF2_HMAC_GOSTR3411_2012_256.UseVisualStyleBackColor = true;
            // 
            // radioPBKDF2_HMAC_GOSTR3411_2012_512
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_GOSTR3411_2012_512, "radioPBKDF2_HMAC_GOSTR3411_2012_512");
            this.radioPBKDF2_HMAC_GOSTR3411_2012_512.Name = "radioPBKDF2_HMAC_GOSTR3411_2012_512";
            this.radioPBKDF2_HMAC_GOSTR3411_2012_512.TabStop = true;
            this.radioPBKDF2_HMAC_GOSTR3411_2012_512.UseVisualStyleBackColor = true;
            // 
            // radioPBKDF2_HMAC_GOSTR3411_1994
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_GOSTR3411_1994, "radioPBKDF2_HMAC_GOSTR3411_1994");
            this.radioPBKDF2_HMAC_GOSTR3411_1994.Checked = true;
            this.radioPBKDF2_HMAC_GOSTR3411_1994.Name = "radioPBKDF2_HMAC_GOSTR3411_1994";
            this.radioPBKDF2_HMAC_GOSTR3411_1994.TabStop = true;
            this.radioPBKDF2_HMAC_GOSTR3411_1994.UseVisualStyleBackColor = true;
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
            // labelSaltLengthPBE
            // 
            resources.ApplyResources(this.labelSaltLengthPBE, "labelSaltLengthPBE");
            this.labelSaltLengthPBE.Name = "labelSaltLengthPBE";
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
            this.groupBoxHash.Controls.Add(this.radioGOSTR3411_2012_256);
            this.groupBoxHash.Controls.Add(this.radioGOSTR3411_2012_512);
            this.groupBoxHash.Controls.Add(this.radioGOSTR3411_1994);
            this.groupBoxHash.Name = "groupBoxHash";
            this.groupBoxHash.TabStop = false;
            // 
            // radioGOSTR3411_2012_256
            // 
            resources.ApplyResources(this.radioGOSTR3411_2012_256, "radioGOSTR3411_2012_256");
            this.radioGOSTR3411_2012_256.Name = "radioGOSTR3411_2012_256";
            this.radioGOSTR3411_2012_256.TabStop = true;
            this.radioGOSTR3411_2012_256.UseVisualStyleBackColor = true;
            // 
            // radioGOSTR3411_2012_512
            // 
            resources.ApplyResources(this.radioGOSTR3411_2012_512, "radioGOSTR3411_2012_512");
            this.radioGOSTR3411_2012_512.Name = "radioGOSTR3411_2012_512";
            this.radioGOSTR3411_2012_512.TabStop = true;
            this.radioGOSTR3411_2012_512.UseVisualStyleBackColor = true;
            // 
            // radioGOSTR3411_1994
            // 
            resources.ApplyResources(this.radioGOSTR3411_1994, "radioGOSTR3411_1994");
            this.radioGOSTR3411_1994.Checked = true;
            this.radioGOSTR3411_1994.Name = "radioGOSTR3411_1994";
            this.radioGOSTR3411_1994.TabStop = true;
            this.radioGOSTR3411_1994.UseVisualStyleBackColor = true;
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
        private System.Windows.Forms.RadioButton radioGOST28147_A;
        private System.Windows.Forms.GroupBox groupBoxPBES2KDF;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_GOSTR3411_1994;
        private System.Windows.Forms.RadioButton radioGOST28147_D;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_GOSTR3411_2012_512;
        private System.Windows.Forms.GroupBox groupBoxPBE;
        private System.Windows.Forms.RadioButton radioGOST28147_C;
        private System.Windows.Forms.RadioButton radioGOST28147_B;
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
        private System.Windows.Forms.RadioButton radioGOSTR3411_2012_512;
        private System.Windows.Forms.RadioButton radioGOSTR3411_1994;
        private System.Windows.Forms.RadioButton radioGOSTR3411_2012_256;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_GOSTR3411_2012_256;
        private System.Windows.Forms.RadioButton radioKuznyechik;
        private System.Windows.Forms.RadioButton radioMagma;
    }
}
