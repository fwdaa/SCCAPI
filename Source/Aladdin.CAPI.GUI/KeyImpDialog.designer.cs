namespace Aladdin.CAPI.GUI
{
	partial class KeyImpDialog
	{
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.IContainer components = null;

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing && (components != null))
			{
				components.Dispose();
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(KeyImpDialog));
            this.textBoxName = new System.Windows.Forms.TextBox();
            this.labelName = new System.Windows.Forms.Label();
            this.checkBoxGUID = new System.Windows.Forms.CheckBox();
            this.buttonImport = new System.Windows.Forms.Button();
            this.buttonCancel = new System.Windows.Forms.Button();
            this.labelContainer = new System.Windows.Forms.Label();
            this.textBoxContainer = new System.Windows.Forms.TextBox();
            this.checkBoxExport = new System.Windows.Forms.CheckBox();
            this.groupBoxKeyUsage = new System.Windows.Forms.GroupBox();
            this.checkBoxDataEncipherment = new System.Windows.Forms.CheckBox();
            this.checkBoxKeyAgreement = new System.Windows.Forms.CheckBox();
            this.checkBoxKeyEncipherment = new System.Windows.Forms.CheckBox();
            this.checkBoxNonRepudiation = new System.Windows.Forms.CheckBox();
            this.checkBoxCrlSignature = new System.Windows.Forms.CheckBox();
            this.checkBoxCertificateSignature = new System.Windows.Forms.CheckBox();
            this.checkBoxDigitalSignature = new System.Windows.Forms.CheckBox();
            this.groupBoxKeyUsage.SuspendLayout();
            this.SuspendLayout();
            // 
            // textBoxName
            // 
            resources.ApplyResources(this.textBoxName, "textBoxName");
            this.textBoxName.Name = "textBoxName";
            this.textBoxName.TextChanged += new System.EventHandler(this.OnNameChanged);
            // 
            // labelName
            // 
            resources.ApplyResources(this.labelName, "labelName");
            this.labelName.Name = "labelName";
            // 
            // checkBoxGUID
            // 
            resources.ApplyResources(this.checkBoxGUID, "checkBoxGUID");
            this.checkBoxGUID.Name = "checkBoxGUID";
            this.checkBoxGUID.UseVisualStyleBackColor = true;
            this.checkBoxGUID.Click += new System.EventHandler(this.OnGuidChanged);
            // 
            // buttonImport
            // 
            resources.ApplyResources(this.buttonImport, "buttonImport");
            this.buttonImport.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonImport.Name = "buttonImport";
            this.buttonImport.UseVisualStyleBackColor = true;
            this.buttonImport.Click += new System.EventHandler(this.OnImportKeyPair);
            // 
            // buttonCancel
            // 
            resources.ApplyResources(this.buttonCancel, "buttonCancel");
            this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.buttonCancel.Name = "buttonCancel";
            this.buttonCancel.UseVisualStyleBackColor = true;
            // 
            // labelContainer
            // 
            resources.ApplyResources(this.labelContainer, "labelContainer");
            this.labelContainer.Name = "labelContainer";
            // 
            // textBoxContainer
            // 
            resources.ApplyResources(this.textBoxContainer, "textBoxContainer");
            this.textBoxContainer.Name = "textBoxContainer";
            this.textBoxContainer.ReadOnly = true;
            // 
            // checkBoxExport
            // 
            resources.ApplyResources(this.checkBoxExport, "checkBoxExport");
            this.checkBoxExport.Name = "checkBoxExport";
            this.checkBoxExport.UseVisualStyleBackColor = true;
            // 
            // groupBoxKeyUsage
            // 
            resources.ApplyResources(this.groupBoxKeyUsage, "groupBoxKeyUsage");
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxDataEncipherment);
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxKeyAgreement);
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxKeyEncipherment);
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxNonRepudiation);
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxCrlSignature);
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxCertificateSignature);
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxDigitalSignature);
            this.groupBoxKeyUsage.Name = "groupBoxKeyUsage";
            this.groupBoxKeyUsage.TabStop = false;
            // 
            // checkBoxDataEncipherment
            // 
            resources.ApplyResources(this.checkBoxDataEncipherment, "checkBoxDataEncipherment");
            this.checkBoxDataEncipherment.Name = "checkBoxDataEncipherment";
            this.checkBoxDataEncipherment.UseVisualStyleBackColor = true;
            // 
            // checkBoxKeyAgreement
            // 
            resources.ApplyResources(this.checkBoxKeyAgreement, "checkBoxKeyAgreement");
            this.checkBoxKeyAgreement.Name = "checkBoxKeyAgreement";
            this.checkBoxKeyAgreement.UseVisualStyleBackColor = true;
            // 
            // checkBoxKeyEncipherment
            // 
            resources.ApplyResources(this.checkBoxKeyEncipherment, "checkBoxKeyEncipherment");
            this.checkBoxKeyEncipherment.Name = "checkBoxKeyEncipherment";
            this.checkBoxKeyEncipherment.UseVisualStyleBackColor = true;
            // 
            // checkBoxNonRepudiation
            // 
            resources.ApplyResources(this.checkBoxNonRepudiation, "checkBoxNonRepudiation");
            this.checkBoxNonRepudiation.Name = "checkBoxNonRepudiation";
            this.checkBoxNonRepudiation.UseVisualStyleBackColor = true;
            // 
            // checkBoxCrlSignature
            // 
            resources.ApplyResources(this.checkBoxCrlSignature, "checkBoxCrlSignature");
            this.checkBoxCrlSignature.Name = "checkBoxCrlSignature";
            this.checkBoxCrlSignature.UseVisualStyleBackColor = true;
            // 
            // checkBoxCertificateSignature
            // 
            resources.ApplyResources(this.checkBoxCertificateSignature, "checkBoxCertificateSignature");
            this.checkBoxCertificateSignature.Name = "checkBoxCertificateSignature";
            this.checkBoxCertificateSignature.UseVisualStyleBackColor = true;
            // 
            // checkBoxDigitalSignature
            // 
            resources.ApplyResources(this.checkBoxDigitalSignature, "checkBoxDigitalSignature");
            this.checkBoxDigitalSignature.Name = "checkBoxDigitalSignature";
            this.checkBoxDigitalSignature.UseVisualStyleBackColor = true;
            // 
            // KeyImpDialog
            // 
            this.AcceptButton = this.buttonImport;
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.groupBoxKeyUsage);
            this.Controls.Add(this.checkBoxExport);
            this.Controls.Add(this.labelContainer);
            this.Controls.Add(this.textBoxContainer);
            this.Controls.Add(this.buttonCancel);
            this.Controls.Add(this.buttonImport);
            this.Controls.Add(this.checkBoxGUID);
            this.Controls.Add(this.labelName);
            this.Controls.Add(this.textBoxName);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "KeyImpDialog";
            this.groupBoxKeyUsage.ResumeLayout(false);
            this.groupBoxKeyUsage.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

		}

		#endregion

		private System.Windows.Forms.TextBox textBoxName;
		private System.Windows.Forms.Label labelName;
		private System.Windows.Forms.CheckBox checkBoxGUID;
		private System.Windows.Forms.Button buttonImport;
        private System.Windows.Forms.Button buttonCancel;
		private System.Windows.Forms.Label labelContainer;
        private System.Windows.Forms.TextBox textBoxContainer;
        private System.Windows.Forms.CheckBox checkBoxExport;
        private System.Windows.Forms.GroupBox groupBoxKeyUsage;
        private System.Windows.Forms.CheckBox checkBoxDataEncipherment;
        private System.Windows.Forms.CheckBox checkBoxKeyAgreement;
        private System.Windows.Forms.CheckBox checkBoxKeyEncipherment;
        private System.Windows.Forms.CheckBox checkBoxNonRepudiation;
        private System.Windows.Forms.CheckBox checkBoxCrlSignature;
        private System.Windows.Forms.CheckBox checkBoxCertificateSignature;
        private System.Windows.Forms.CheckBox checkBoxDigitalSignature;
	}
}