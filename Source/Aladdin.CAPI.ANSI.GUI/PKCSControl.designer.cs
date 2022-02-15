namespace Aladdin.CAPI.ANSI.GUI
{
	public partial class PKCSControl
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(PKCSControl));
            this.TitleLabel = new System.Windows.Forms.Label();
            this.radioMD2_DES_CBC = new System.Windows.Forms.RadioButton();
            this.radioMD5_DES_CBC = new System.Windows.Forms.RadioButton();
            this.radioMD2_RC2_64_CBC = new System.Windows.Forms.RadioButton();
            this.radioMD5_RC2_64_CBC = new System.Windows.Forms.RadioButton();
            this.radioSHA1_DES_CBC = new System.Windows.Forms.RadioButton();
            this.radioSHA1_RC2_64_CBC = new System.Windows.Forms.RadioButton();
            this.radioSHA1_RC4_128 = new System.Windows.Forms.RadioButton();
            this.radioSHA1_RC4_40 = new System.Windows.Forms.RadioButton();
            this.radioSHA1_RC2_128_CBC = new System.Windows.Forms.RadioButton();
            this.radioSHA1_RC2_40_CBC = new System.Windows.Forms.RadioButton();
            this.radioSHA1_TDES_192_CBC = new System.Windows.Forms.RadioButton();
            this.radioSHA1_TDES_128_CBC = new System.Windows.Forms.RadioButton();
            this.groupBoxPKCS5 = new System.Windows.Forms.GroupBox();
            this.groupBoxPKCS12 = new System.Windows.Forms.GroupBox();
            this.groupBoxPBE = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBE = new System.Windows.Forms.Label();
            this.textBoxIterationsPBE = new System.Windows.Forms.TextBox();
            this.labelSaltLengthPBE = new System.Windows.Forms.Label();
            this.textBoxSaltLengthPBE = new System.Windows.Forms.TextBox();
            this.groupBoxHash = new System.Windows.Forms.GroupBox();
            this.radioMD2 = new System.Windows.Forms.RadioButton();
            this.radioMD5 = new System.Windows.Forms.RadioButton();
            this.radioSHA1 = new System.Windows.Forms.RadioButton();
            this.groupBoxPBMAC = new System.Windows.Forms.GroupBox();
            this.labelIterationsPBMAC = new System.Windows.Forms.Label();
            this.textBoxIterationsPBMAC = new System.Windows.Forms.TextBox();
            this.labelSaltLengthPBMAC = new System.Windows.Forms.Label();
            this.textBoxSaltLengthPBMAC = new System.Windows.Forms.TextBox();
            this.groupBoxPKCS5.SuspendLayout();
            this.groupBoxPKCS12.SuspendLayout();
            this.groupBoxPBE.SuspendLayout();
            this.groupBoxHash.SuspendLayout();
            this.groupBoxPBMAC.SuspendLayout();
            this.SuspendLayout();
            // 
            // TitleLabel
            // 
            this.TitleLabel.BackColor = System.Drawing.Color.Transparent;
            resources.ApplyResources(this.TitleLabel, "TitleLabel");
            this.TitleLabel.Name = "TitleLabel";
            // 
            // radioMD2_DES_CBC
            // 
            resources.ApplyResources(this.radioMD2_DES_CBC, "radioMD2_DES_CBC");
            this.radioMD2_DES_CBC.Name = "radioMD2_DES_CBC";
            this.radioMD2_DES_CBC.TabStop = true;
            this.radioMD2_DES_CBC.UseVisualStyleBackColor = true;
            this.radioMD2_DES_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioMD5_DES_CBC
            // 
            resources.ApplyResources(this.radioMD5_DES_CBC, "radioMD5_DES_CBC");
            this.radioMD5_DES_CBC.Name = "radioMD5_DES_CBC";
            this.radioMD5_DES_CBC.TabStop = true;
            this.radioMD5_DES_CBC.UseVisualStyleBackColor = true;
            this.radioMD5_DES_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioMD2_RC2_64_CBC
            // 
            resources.ApplyResources(this.radioMD2_RC2_64_CBC, "radioMD2_RC2_64_CBC");
            this.radioMD2_RC2_64_CBC.Name = "radioMD2_RC2_64_CBC";
            this.radioMD2_RC2_64_CBC.TabStop = true;
            this.radioMD2_RC2_64_CBC.UseVisualStyleBackColor = true;
            this.radioMD2_RC2_64_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioMD5_RC2_64_CBC
            // 
            resources.ApplyResources(this.radioMD5_RC2_64_CBC, "radioMD5_RC2_64_CBC");
            this.radioMD5_RC2_64_CBC.Name = "radioMD5_RC2_64_CBC";
            this.radioMD5_RC2_64_CBC.TabStop = true;
            this.radioMD5_RC2_64_CBC.UseVisualStyleBackColor = true;
            this.radioMD5_RC2_64_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_DES_CBC
            // 
            resources.ApplyResources(this.radioSHA1_DES_CBC, "radioSHA1_DES_CBC");
            this.radioSHA1_DES_CBC.Name = "radioSHA1_DES_CBC";
            this.radioSHA1_DES_CBC.TabStop = true;
            this.radioSHA1_DES_CBC.UseVisualStyleBackColor = true;
            this.radioSHA1_DES_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_RC2_64_CBC
            // 
            resources.ApplyResources(this.radioSHA1_RC2_64_CBC, "radioSHA1_RC2_64_CBC");
            this.radioSHA1_RC2_64_CBC.Name = "radioSHA1_RC2_64_CBC";
            this.radioSHA1_RC2_64_CBC.TabStop = true;
            this.radioSHA1_RC2_64_CBC.UseVisualStyleBackColor = true;
            this.radioSHA1_RC2_64_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_RC4_128
            // 
            resources.ApplyResources(this.radioSHA1_RC4_128, "radioSHA1_RC4_128");
            this.radioSHA1_RC4_128.Name = "radioSHA1_RC4_128";
            this.radioSHA1_RC4_128.UseVisualStyleBackColor = true;
            this.radioSHA1_RC4_128.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_RC4_40
            // 
            resources.ApplyResources(this.radioSHA1_RC4_40, "radioSHA1_RC4_40");
            this.radioSHA1_RC4_40.Name = "radioSHA1_RC4_40";
            this.radioSHA1_RC4_40.UseVisualStyleBackColor = true;
            this.radioSHA1_RC4_40.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_RC2_128_CBC
            // 
            resources.ApplyResources(this.radioSHA1_RC2_128_CBC, "radioSHA1_RC2_128_CBC");
            this.radioSHA1_RC2_128_CBC.Name = "radioSHA1_RC2_128_CBC";
            this.radioSHA1_RC2_128_CBC.UseVisualStyleBackColor = true;
            this.radioSHA1_RC2_128_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_RC2_40_CBC
            // 
            resources.ApplyResources(this.radioSHA1_RC2_40_CBC, "radioSHA1_RC2_40_CBC");
            this.radioSHA1_RC2_40_CBC.Name = "radioSHA1_RC2_40_CBC";
            this.radioSHA1_RC2_40_CBC.UseVisualStyleBackColor = true;
            this.radioSHA1_RC2_40_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_TDES_192_CBC
            // 
            resources.ApplyResources(this.radioSHA1_TDES_192_CBC, "radioSHA1_TDES_192_CBC");
            this.radioSHA1_TDES_192_CBC.Checked = true;
            this.radioSHA1_TDES_192_CBC.Name = "radioSHA1_TDES_192_CBC";
            this.radioSHA1_TDES_192_CBC.TabStop = true;
            this.radioSHA1_TDES_192_CBC.UseVisualStyleBackColor = true;
            this.radioSHA1_TDES_192_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // radioSHA1_TDES_128_CBC
            // 
            resources.ApplyResources(this.radioSHA1_TDES_128_CBC, "radioSHA1_TDES_128_CBC");
            this.radioSHA1_TDES_128_CBC.Name = "radioSHA1_TDES_128_CBC";
            this.radioSHA1_TDES_128_CBC.UseVisualStyleBackColor = true;
            this.radioSHA1_TDES_128_CBC.CheckedChanged += new System.EventHandler(this.OnCheckedChanged);
            // 
            // groupBoxPKCS5
            // 
            this.groupBoxPKCS5.Controls.Add(this.radioMD2_RC2_64_CBC);
            this.groupBoxPKCS5.Controls.Add(this.radioMD5_DES_CBC);
            this.groupBoxPKCS5.Controls.Add(this.radioSHA1_RC2_64_CBC);
            this.groupBoxPKCS5.Controls.Add(this.radioMD2_DES_CBC);
            this.groupBoxPKCS5.Controls.Add(this.radioSHA1_DES_CBC);
            this.groupBoxPKCS5.Controls.Add(this.radioMD5_RC2_64_CBC);
            resources.ApplyResources(this.groupBoxPKCS5, "groupBoxPKCS5");
            this.groupBoxPKCS5.Name = "groupBoxPKCS5";
            this.groupBoxPKCS5.TabStop = false;
            // 
            // groupBoxPKCS12
            // 
            this.groupBoxPKCS12.Controls.Add(this.radioSHA1_RC2_40_CBC);
            this.groupBoxPKCS12.Controls.Add(this.radioSHA1_RC4_128);
            this.groupBoxPKCS12.Controls.Add(this.radioSHA1_RC4_40);
            this.groupBoxPKCS12.Controls.Add(this.radioSHA1_TDES_128_CBC);
            this.groupBoxPKCS12.Controls.Add(this.radioSHA1_RC2_128_CBC);
            this.groupBoxPKCS12.Controls.Add(this.radioSHA1_TDES_192_CBC);
            resources.ApplyResources(this.groupBoxPKCS12, "groupBoxPKCS12");
            this.groupBoxPKCS12.Name = "groupBoxPKCS12";
            this.groupBoxPKCS12.TabStop = false;
            // 
            // groupBoxPBE
            // 
            this.groupBoxPBE.Controls.Add(this.labelIterationsPBE);
            this.groupBoxPBE.Controls.Add(this.textBoxIterationsPBE);
            this.groupBoxPBE.Controls.Add(this.labelSaltLengthPBE);
            this.groupBoxPBE.Controls.Add(this.textBoxSaltLengthPBE);
            this.groupBoxPBE.Controls.Add(this.groupBoxPKCS12);
            this.groupBoxPBE.Controls.Add(this.groupBoxPKCS5);
            resources.ApplyResources(this.groupBoxPBE, "groupBoxPBE");
            this.groupBoxPBE.Name = "groupBoxPBE";
            this.groupBoxPBE.TabStop = false;
            // 
            // labelIterationsPBE
            // 
            resources.ApplyResources(this.labelIterationsPBE, "labelIterationsPBE");
            this.labelIterationsPBE.Name = "labelIterationsPBE";
            // 
            // textBoxIterationsPBE
            // 
            resources.ApplyResources(this.textBoxIterationsPBE, "textBoxIterationsPBE");
            this.textBoxIterationsPBE.Name = "textBoxIterationsPBE";
            this.textBoxIterationsPBE.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // labelSaltLengthPBE
            // 
            resources.ApplyResources(this.labelSaltLengthPBE, "labelSaltLengthPBE");
            this.labelSaltLengthPBE.Name = "labelSaltLengthPBE";
            // 
            // textBoxSaltLengthPBE
            // 
            resources.ApplyResources(this.textBoxSaltLengthPBE, "textBoxSaltLengthPBE");
            this.textBoxSaltLengthPBE.Name = "textBoxSaltLengthPBE";
            this.textBoxSaltLengthPBE.Validating += new System.ComponentModel.CancelEventHandler(this.OnValidating);
            // 
            // groupBoxHash
            // 
            this.groupBoxHash.Controls.Add(this.radioMD2);
            this.groupBoxHash.Controls.Add(this.radioMD5);
            this.groupBoxHash.Controls.Add(this.radioSHA1);
            resources.ApplyResources(this.groupBoxHash, "groupBoxHash");
            this.groupBoxHash.Name = "groupBoxHash";
            this.groupBoxHash.TabStop = false;
            // 
            // radioMD2
            // 
            resources.ApplyResources(this.radioMD2, "radioMD2");
            this.radioMD2.Name = "radioMD2";
            this.radioMD2.TabStop = true;
            this.radioMD2.UseVisualStyleBackColor = true;
            // 
            // radioMD5
            // 
            resources.ApplyResources(this.radioMD5, "radioMD5");
            this.radioMD5.Name = "radioMD5";
            this.radioMD5.TabStop = true;
            this.radioMD5.UseVisualStyleBackColor = true;
            // 
            // radioSHA1
            // 
            resources.ApplyResources(this.radioSHA1, "radioSHA1");
            this.radioSHA1.Checked = true;
            this.radioSHA1.Name = "radioSHA1";
            this.radioSHA1.TabStop = true;
            this.radioSHA1.UseVisualStyleBackColor = true;
            // 
            // groupBoxPBMAC
            // 
            this.groupBoxPBMAC.Controls.Add(this.labelIterationsPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.textBoxIterationsPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.labelSaltLengthPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.textBoxSaltLengthPBMAC);
            this.groupBoxPBMAC.Controls.Add(this.groupBoxHash);
            resources.ApplyResources(this.groupBoxPBMAC, "groupBoxPBMAC");
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
            // PKCSControl
            // 
            this.Controls.Add(this.groupBoxPBMAC);
            this.Controls.Add(this.groupBoxPBE);
            resources.ApplyResources(this, "$this");
            this.Name = "PKCSControl";
            this.Load += new System.EventHandler(this.OnLoad);
            this.groupBoxPKCS5.ResumeLayout(false);
            this.groupBoxPKCS5.PerformLayout();
            this.groupBoxPKCS12.ResumeLayout(false);
            this.groupBoxPKCS12.PerformLayout();
            this.groupBoxPBE.ResumeLayout(false);
            this.groupBoxPBE.PerformLayout();
            this.groupBoxHash.ResumeLayout(false);
            this.groupBoxHash.PerformLayout();
            this.groupBoxPBMAC.ResumeLayout(false);
            this.groupBoxPBMAC.PerformLayout();
            this.ResumeLayout(false);

		}
		#endregion

        private System.Windows.Forms.Label TitleLabel;
        private System.Windows.Forms.RadioButton radioMD2_DES_CBC;
        private System.Windows.Forms.RadioButton radioMD5_DES_CBC;
        private System.Windows.Forms.RadioButton radioMD2_RC2_64_CBC;
        private System.Windows.Forms.RadioButton radioMD5_RC2_64_CBC;
        private System.Windows.Forms.RadioButton radioSHA1_DES_CBC;
        private System.Windows.Forms.RadioButton radioSHA1_RC2_64_CBC;
        private System.Windows.Forms.RadioButton radioSHA1_RC4_128;
        private System.Windows.Forms.RadioButton radioSHA1_RC4_40;
        private System.Windows.Forms.RadioButton radioSHA1_RC2_128_CBC;
        private System.Windows.Forms.RadioButton radioSHA1_RC2_40_CBC;
        private System.Windows.Forms.RadioButton radioSHA1_TDES_192_CBC;
        private System.Windows.Forms.RadioButton radioSHA1_TDES_128_CBC;
        private System.Windows.Forms.GroupBox groupBoxPKCS5;
        private System.Windows.Forms.GroupBox groupBoxPKCS12;
        private System.Windows.Forms.GroupBox groupBoxPBE;
        private System.Windows.Forms.Label labelIterationsPBE;
        private System.Windows.Forms.TextBox textBoxIterationsPBE;
        private System.Windows.Forms.Label labelSaltLengthPBE;
        private System.Windows.Forms.TextBox textBoxSaltLengthPBE;
        private System.Windows.Forms.GroupBox groupBoxHash;
        private System.Windows.Forms.RadioButton radioMD2;
        private System.Windows.Forms.RadioButton radioMD5;
        private System.Windows.Forms.GroupBox groupBoxPBMAC;
        private System.Windows.Forms.Label labelIterationsPBMAC;
        private System.Windows.Forms.TextBox textBoxIterationsPBMAC;
        private System.Windows.Forms.Label labelSaltLengthPBMAC;
        private System.Windows.Forms.TextBox textBoxSaltLengthPBMAC;
        private System.Windows.Forms.RadioButton radioSHA1;

	}
}
