namespace Aladdin.CAPI.STB.GUI
{
	public partial class STB34101Control
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(STB34101Control));
            this.TitleLabel = new System.Windows.Forms.Label();
            this.groupBoxPBES2Cipher = new System.Windows.Forms.GroupBox();
            this.radioSTB34101_CTR_256 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CFB_256 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CBC_256 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CTR_192 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CFB_192 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CBC_192 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CTR_128 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CFB_128 = new System.Windows.Forms.RadioButton();
            this.radioSTB34101_CBC_128 = new System.Windows.Forms.RadioButton();
            this.groupBoxPBES2KDF = new System.Windows.Forms.GroupBox();
            this.radioPBKDF2_HMAC_STB34101 = new System.Windows.Forms.RadioButton();
            this.labelIterationsPBE = new System.Windows.Forms.Label();
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
            this.radioSTB34101 = new System.Windows.Forms.RadioButton();
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
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CTR_256);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CFB_256);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CBC_256);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CTR_192);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CFB_192);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CBC_192);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CTR_128);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CFB_128);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioSTB34101_CBC_128);
            this.groupBoxPBES2Cipher.Name = "groupBoxPBES2Cipher";
            this.groupBoxPBES2Cipher.TabStop = false;
            // 
            // radioSTB34101_CTR_256
            // 
            resources.ApplyResources(this.radioSTB34101_CTR_256, "radioSTB34101_CTR_256");
            this.radioSTB34101_CTR_256.Name = "radioSTB34101_CTR_256";
            this.radioSTB34101_CTR_256.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CFB_256
            // 
            resources.ApplyResources(this.radioSTB34101_CFB_256, "radioSTB34101_CFB_256");
            this.radioSTB34101_CFB_256.Name = "radioSTB34101_CFB_256";
            this.radioSTB34101_CFB_256.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CBC_256
            // 
            resources.ApplyResources(this.radioSTB34101_CBC_256, "radioSTB34101_CBC_256");
            this.radioSTB34101_CBC_256.Checked = true;
            this.radioSTB34101_CBC_256.Name = "radioSTB34101_CBC_256";
            this.radioSTB34101_CBC_256.TabStop = true;
            this.radioSTB34101_CBC_256.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CTR_192
            // 
            resources.ApplyResources(this.radioSTB34101_CTR_192, "radioSTB34101_CTR_192");
            this.radioSTB34101_CTR_192.Name = "radioSTB34101_CTR_192";
            this.radioSTB34101_CTR_192.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CFB_192
            // 
            resources.ApplyResources(this.radioSTB34101_CFB_192, "radioSTB34101_CFB_192");
            this.radioSTB34101_CFB_192.Name = "radioSTB34101_CFB_192";
            this.radioSTB34101_CFB_192.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CBC_192
            // 
            resources.ApplyResources(this.radioSTB34101_CBC_192, "radioSTB34101_CBC_192");
            this.radioSTB34101_CBC_192.Name = "radioSTB34101_CBC_192";
            this.radioSTB34101_CBC_192.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CTR_128
            // 
            resources.ApplyResources(this.radioSTB34101_CTR_128, "radioSTB34101_CTR_128");
            this.radioSTB34101_CTR_128.Name = "radioSTB34101_CTR_128";
            this.radioSTB34101_CTR_128.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CFB_128
            // 
            resources.ApplyResources(this.radioSTB34101_CFB_128, "radioSTB34101_CFB_128");
            this.radioSTB34101_CFB_128.Name = "radioSTB34101_CFB_128";
            this.radioSTB34101_CFB_128.UseVisualStyleBackColor = true;
            // 
            // radioSTB34101_CBC_128
            // 
            resources.ApplyResources(this.radioSTB34101_CBC_128, "radioSTB34101_CBC_128");
            this.radioSTB34101_CBC_128.Name = "radioSTB34101_CBC_128";
            this.radioSTB34101_CBC_128.UseVisualStyleBackColor = true;
            // 
            // groupBoxPBES2KDF
            // 
            resources.ApplyResources(this.groupBoxPBES2KDF, "groupBoxPBES2KDF");
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_STB34101);
            this.groupBoxPBES2KDF.Controls.Add(this.labelIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.labelSaltLengthPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxSaltLengthPBE);
            this.groupBoxPBES2KDF.Name = "groupBoxPBES2KDF";
            this.groupBoxPBES2KDF.TabStop = false;
            // 
            // radioPBKDF2_HMAC_STB34101
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_STB34101, "radioPBKDF2_HMAC_STB34101");
            this.radioPBKDF2_HMAC_STB34101.Checked = true;
            this.radioPBKDF2_HMAC_STB34101.Name = "radioPBKDF2_HMAC_STB34101";
            this.radioPBKDF2_HMAC_STB34101.TabStop = true;
            this.radioPBKDF2_HMAC_STB34101.UseVisualStyleBackColor = true;
            // 
            // labelIterationsPBE
            // 
            resources.ApplyResources(this.labelIterationsPBE, "labelIterationsPBE");
            this.labelIterationsPBE.Name = "labelIterationsPBE";
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
            this.groupBoxHash.Controls.Add(this.radioSTB34101);
            this.groupBoxHash.Name = "groupBoxHash";
            this.groupBoxHash.TabStop = false;
            // 
            // radioSTB34101
            // 
            resources.ApplyResources(this.radioSTB34101, "radioSTB34101");
            this.radioSTB34101.Checked = true;
            this.radioSTB34101.Name = "radioSTB34101";
            this.radioSTB34101.TabStop = true;
            this.radioSTB34101.UseVisualStyleBackColor = true;
            // 
            // STB34101Control
            // 
            resources.ApplyResources(this, "$this");
            this.Controls.Add(this.groupBoxPBMAC);
            this.Controls.Add(this.groupBoxPBE);
            this.Name = "STB34101Control";
            this.Load += new System.EventHandler(this.OnLoad);
            this.groupBoxPBES2Cipher.ResumeLayout(false);
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
        private System.Windows.Forms.GroupBox groupBoxPBES2KDF;
        private System.Windows.Forms.GroupBox groupBoxPBE;
        private System.Windows.Forms.RadioButton radioSTB34101_CFB_128;
        private System.Windows.Forms.RadioButton radioSTB34101_CBC_128;
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
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_STB34101;
        private System.Windows.Forms.RadioButton radioSTB34101_CTR_256;
        private System.Windows.Forms.RadioButton radioSTB34101_CFB_256;
        private System.Windows.Forms.RadioButton radioSTB34101_CBC_256;
        private System.Windows.Forms.RadioButton radioSTB34101_CTR_192;
        private System.Windows.Forms.RadioButton radioSTB34101_CFB_192;
        private System.Windows.Forms.RadioButton radioSTB34101_CBC_192;
        private System.Windows.Forms.RadioButton radioSTB34101_CTR_128;
        private System.Windows.Forms.RadioButton radioSTB34101;

	}
}
