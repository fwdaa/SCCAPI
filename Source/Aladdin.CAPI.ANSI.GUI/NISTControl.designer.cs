namespace Aladdin.CAPI.ANSI.GUI
{
	public partial class NISTControl
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(NISTControl));
            this.TitleLabel = new System.Windows.Forms.Label();
            this.groupBoxPBES2Cipher = new System.Windows.Forms.GroupBox();
            this.radioAES_256_CFB = new System.Windows.Forms.RadioButton();
            this.radioAES_256_OFB = new System.Windows.Forms.RadioButton();
            this.radioAES_192_CFB = new System.Windows.Forms.RadioButton();
            this.radioAES_192_OFB = new System.Windows.Forms.RadioButton();
            this.radioAES_128_CFB = new System.Windows.Forms.RadioButton();
            this.radioAES_128_OFB = new System.Windows.Forms.RadioButton();
            this.radioAES_256_CBC = new System.Windows.Forms.RadioButton();
            this.radioAES_192_CBC = new System.Windows.Forms.RadioButton();
            this.radioAES_128_CBC = new System.Windows.Forms.RadioButton();
            this.groupBoxPBES2KDF = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBE = new System.Windows.Forms.Label();
            this.radioPBKDF2_HMAC_SHA2_224 = new System.Windows.Forms.RadioButton();
            this.radioPBKDF2_HMAC_SHA2_512 = new System.Windows.Forms.RadioButton();
            this.radioPBKDF2_HMAC_SHA2_384 = new System.Windows.Forms.RadioButton();
            this.textBoxIterationsPBE = new System.Windows.Forms.TextBox();
            this.radioPBKDF2_HMAC_SHA2_256 = new System.Windows.Forms.RadioButton();
            this.textBoxSaltLengthPBE = new System.Windows.Forms.TextBox();
            this.radioPBKDF2_HMAC_SHA1 = new System.Windows.Forms.RadioButton();
            this.labelSaltLengthPBE = new System.Windows.Forms.Label();
            this.groupBoxPBE = new System.Windows.Forms.GroupBox();
            this.groupBoxPBMAC = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBMAC = new System.Windows.Forms.Label();
            this.textBoxIterationsPBMAC = new System.Windows.Forms.TextBox();
            this.labelSaltLengthPBMAC = new System.Windows.Forms.Label();
            this.textBoxSaltLengthPBMAC = new System.Windows.Forms.TextBox();
            this.groupBoxHash = new System.Windows.Forms.GroupBox();
            this.radioSHA2_224 = new System.Windows.Forms.RadioButton();
            this.radioSHA2_512 = new System.Windows.Forms.RadioButton();
            this.radioSHA2_256 = new System.Windows.Forms.RadioButton();
            this.radioSHA2_384 = new System.Windows.Forms.RadioButton();
            this.radioSHA1 = new System.Windows.Forms.RadioButton();
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
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_256_CFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_256_OFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_192_CFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_192_OFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_128_CFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_128_OFB);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_256_CBC);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_192_CBC);
            this.groupBoxPBES2Cipher.Controls.Add(this.radioAES_128_CBC);
            this.groupBoxPBES2Cipher.Name = "groupBoxPBES2Cipher";
            this.groupBoxPBES2Cipher.TabStop = false;
            // 
            // radioAES_256_CFB
            // 
            resources.ApplyResources(this.radioAES_256_CFB, "radioAES_256_CFB");
            this.radioAES_256_CFB.Name = "radioAES_256_CFB";
            this.radioAES_256_CFB.TabStop = true;
            this.radioAES_256_CFB.UseVisualStyleBackColor = true;
            // 
            // radioAES_256_OFB
            // 
            resources.ApplyResources(this.radioAES_256_OFB, "radioAES_256_OFB");
            this.radioAES_256_OFB.Name = "radioAES_256_OFB";
            this.radioAES_256_OFB.TabStop = true;
            this.radioAES_256_OFB.UseVisualStyleBackColor = true;
            // 
            // radioAES_192_CFB
            // 
            resources.ApplyResources(this.radioAES_192_CFB, "radioAES_192_CFB");
            this.radioAES_192_CFB.Name = "radioAES_192_CFB";
            this.radioAES_192_CFB.TabStop = true;
            this.radioAES_192_CFB.UseVisualStyleBackColor = true;
            // 
            // radioAES_192_OFB
            // 
            resources.ApplyResources(this.radioAES_192_OFB, "radioAES_192_OFB");
            this.radioAES_192_OFB.Name = "radioAES_192_OFB";
            this.radioAES_192_OFB.TabStop = true;
            this.radioAES_192_OFB.UseVisualStyleBackColor = true;
            // 
            // radioAES_128_CFB
            // 
            resources.ApplyResources(this.radioAES_128_CFB, "radioAES_128_CFB");
            this.radioAES_128_CFB.Name = "radioAES_128_CFB";
            this.radioAES_128_CFB.TabStop = true;
            this.radioAES_128_CFB.UseVisualStyleBackColor = true;
            // 
            // radioAES_128_OFB
            // 
            resources.ApplyResources(this.radioAES_128_OFB, "radioAES_128_OFB");
            this.radioAES_128_OFB.Name = "radioAES_128_OFB";
            this.radioAES_128_OFB.TabStop = true;
            this.radioAES_128_OFB.UseVisualStyleBackColor = true;
            // 
            // radioAES_256_CBC
            // 
            resources.ApplyResources(this.radioAES_256_CBC, "radioAES_256_CBC");
            this.radioAES_256_CBC.Checked = true;
            this.radioAES_256_CBC.Name = "radioAES_256_CBC";
            this.radioAES_256_CBC.TabStop = true;
            this.radioAES_256_CBC.UseVisualStyleBackColor = true;
            // 
            // radioAES_192_CBC
            // 
            resources.ApplyResources(this.radioAES_192_CBC, "radioAES_192_CBC");
            this.radioAES_192_CBC.Name = "radioAES_192_CBC";
            this.radioAES_192_CBC.TabStop = true;
            this.radioAES_192_CBC.UseVisualStyleBackColor = true;
            // 
            // radioAES_128_CBC
            // 
            resources.ApplyResources(this.radioAES_128_CBC, "radioAES_128_CBC");
            this.radioAES_128_CBC.Name = "radioAES_128_CBC";
            this.radioAES_128_CBC.TabStop = true;
            this.radioAES_128_CBC.UseVisualStyleBackColor = true;
            // 
            // groupBoxPBES2KDF
            // 
            resources.ApplyResources(this.groupBoxPBES2KDF, "groupBoxPBES2KDF");
            this.groupBoxPBES2KDF.Controls.Add(this.labelIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_SHA2_224);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_SHA2_512);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_SHA2_384);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxIterationsPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_SHA2_256);
            this.groupBoxPBES2KDF.Controls.Add(this.textBoxSaltLengthPBE);
            this.groupBoxPBES2KDF.Controls.Add(this.radioPBKDF2_HMAC_SHA1);
            this.groupBoxPBES2KDF.Controls.Add(this.labelSaltLengthPBE);
            this.groupBoxPBES2KDF.Name = "groupBoxPBES2KDF";
            this.groupBoxPBES2KDF.TabStop = false;
            // 
            // labelIterationsPBE
            // 
            resources.ApplyResources(this.labelIterationsPBE, "labelIterationsPBE");
            this.labelIterationsPBE.Name = "labelIterationsPBE";
            // 
            // radioPBKDF2_HMAC_SHA2_224
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_SHA2_224, "radioPBKDF2_HMAC_SHA2_224");
            this.radioPBKDF2_HMAC_SHA2_224.Name = "radioPBKDF2_HMAC_SHA2_224";
            this.radioPBKDF2_HMAC_SHA2_224.TabStop = true;
            this.radioPBKDF2_HMAC_SHA2_224.UseVisualStyleBackColor = true;
            // 
            // radioPBKDF2_HMAC_SHA2_512
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_SHA2_512, "radioPBKDF2_HMAC_SHA2_512");
            this.radioPBKDF2_HMAC_SHA2_512.Name = "radioPBKDF2_HMAC_SHA2_512";
            this.radioPBKDF2_HMAC_SHA2_512.TabStop = true;
            this.radioPBKDF2_HMAC_SHA2_512.UseVisualStyleBackColor = true;
            // 
            // radioPBKDF2_HMAC_SHA2_384
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_SHA2_384, "radioPBKDF2_HMAC_SHA2_384");
            this.radioPBKDF2_HMAC_SHA2_384.Name = "radioPBKDF2_HMAC_SHA2_384";
            this.radioPBKDF2_HMAC_SHA2_384.TabStop = true;
            this.radioPBKDF2_HMAC_SHA2_384.UseVisualStyleBackColor = true;
            // 
            // textBoxIterationsPBE
            // 
            resources.ApplyResources(this.textBoxIterationsPBE, "textBoxIterationsPBE");
            this.textBoxIterationsPBE.Name = "textBoxIterationsPBE";
            this.textBoxIterationsPBE.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // radioPBKDF2_HMAC_SHA2_256
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_SHA2_256, "radioPBKDF2_HMAC_SHA2_256");
            this.radioPBKDF2_HMAC_SHA2_256.Name = "radioPBKDF2_HMAC_SHA2_256";
            this.radioPBKDF2_HMAC_SHA2_256.TabStop = true;
            this.radioPBKDF2_HMAC_SHA2_256.UseVisualStyleBackColor = true;
            // 
            // textBoxSaltLengthPBE
            // 
            resources.ApplyResources(this.textBoxSaltLengthPBE, "textBoxSaltLengthPBE");
            this.textBoxSaltLengthPBE.Name = "textBoxSaltLengthPBE";
            this.textBoxSaltLengthPBE.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // radioPBKDF2_HMAC_SHA1
            // 
            resources.ApplyResources(this.radioPBKDF2_HMAC_SHA1, "radioPBKDF2_HMAC_SHA1");
            this.radioPBKDF2_HMAC_SHA1.Checked = true;
            this.radioPBKDF2_HMAC_SHA1.Name = "radioPBKDF2_HMAC_SHA1";
            this.radioPBKDF2_HMAC_SHA1.TabStop = true;
            this.radioPBKDF2_HMAC_SHA1.UseVisualStyleBackColor = true;
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
            this.groupBoxHash.Controls.Add(this.radioSHA2_224);
            this.groupBoxHash.Controls.Add(this.radioSHA2_512);
            this.groupBoxHash.Controls.Add(this.radioSHA2_256);
            this.groupBoxHash.Controls.Add(this.radioSHA2_384);
            this.groupBoxHash.Controls.Add(this.radioSHA1);
            this.groupBoxHash.Name = "groupBoxHash";
            this.groupBoxHash.TabStop = false;
            // 
            // radioSHA2_224
            // 
            resources.ApplyResources(this.radioSHA2_224, "radioSHA2_224");
            this.radioSHA2_224.Name = "radioSHA2_224";
            this.radioSHA2_224.TabStop = true;
            this.radioSHA2_224.UseVisualStyleBackColor = true;
            // 
            // radioSHA2_512
            // 
            resources.ApplyResources(this.radioSHA2_512, "radioSHA2_512");
            this.radioSHA2_512.Name = "radioSHA2_512";
            this.radioSHA2_512.TabStop = true;
            this.radioSHA2_512.UseVisualStyleBackColor = true;
            // 
            // radioSHA2_256
            // 
            resources.ApplyResources(this.radioSHA2_256, "radioSHA2_256");
            this.radioSHA2_256.Name = "radioSHA2_256";
            this.radioSHA2_256.TabStop = true;
            this.radioSHA2_256.UseVisualStyleBackColor = true;
            // 
            // radioSHA2_384
            // 
            resources.ApplyResources(this.radioSHA2_384, "radioSHA2_384");
            this.radioSHA2_384.Name = "radioSHA2_384";
            this.radioSHA2_384.TabStop = true;
            this.radioSHA2_384.UseVisualStyleBackColor = true;
            // 
            // radioSHA1
            // 
            resources.ApplyResources(this.radioSHA1, "radioSHA1");
            this.radioSHA1.Checked = true;
            this.radioSHA1.Name = "radioSHA1";
            this.radioSHA1.TabStop = true;
            this.radioSHA1.UseVisualStyleBackColor = true;
            // 
            // NISTControl
            // 
            resources.ApplyResources(this, "$this");
            this.Controls.Add(this.groupBoxPBMAC);
            this.Controls.Add(this.groupBoxPBE);
            this.Name = "NISTControl";
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
        private System.Windows.Forms.RadioButton radioAES_128_CBC;
        private System.Windows.Forms.GroupBox groupBoxPBES2KDF;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_SHA1;
        private System.Windows.Forms.RadioButton radioAES_256_CBC;
        private System.Windows.Forms.RadioButton radioAES_192_CBC;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_SHA2_512;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_SHA2_384;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_SHA2_256;
        private System.Windows.Forms.GroupBox groupBoxPBE;
        private System.Windows.Forms.RadioButton radioAES_256_CFB;
        private System.Windows.Forms.RadioButton radioAES_256_OFB;
        private System.Windows.Forms.RadioButton radioAES_192_CFB;
        private System.Windows.Forms.RadioButton radioAES_192_OFB;
        private System.Windows.Forms.RadioButton radioAES_128_CFB;
        private System.Windows.Forms.RadioButton radioAES_128_OFB;
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
        private System.Windows.Forms.RadioButton radioSHA2_512;
        private System.Windows.Forms.RadioButton radioSHA2_256;
        private System.Windows.Forms.RadioButton radioSHA2_384;
        private System.Windows.Forms.RadioButton radioSHA1;
        private System.Windows.Forms.RadioButton radioSHA2_224;
        private System.Windows.Forms.RadioButton radioPBKDF2_HMAC_SHA2_224;

	}
}
