namespace Aladdin.CAPI.GUI
{
	partial class CertRequestDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CertRequestDialog));
            this.labelSubject = new System.Windows.Forms.Label();
            this.textBoxSubject = new System.Windows.Forms.TextBox();
            this.buttonOK = new System.Windows.Forms.Button();
            this.buttonCancel = new System.Windows.Forms.Button();
            this.labelFrom = new System.Windows.Forms.Label();
            this.labelBefore = new System.Windows.Forms.Label();
            this.dateTimeFrom = new System.Windows.Forms.DateTimePicker();
            this.dateTimeBefore = new System.Windows.Forms.DateTimePicker();
            this.groupBoxKeyUsage = new System.Windows.Forms.GroupBox();
            this.checkBoxDecipherOnly = new System.Windows.Forms.CheckBox();
            this.checkBoxEncipherOnly = new System.Windows.Forms.CheckBox();
            this.checkBoxDataEncipherment = new System.Windows.Forms.CheckBox();
            this.checkBoxKeyAgreement = new System.Windows.Forms.CheckBox();
            this.checkBoxKeyEncipherment = new System.Windows.Forms.CheckBox();
            this.checkBoxNonRepudiation = new System.Windows.Forms.CheckBox();
            this.checkBoxCrlSignature = new System.Windows.Forms.CheckBox();
            this.checkBoxCertificateSignature = new System.Windows.Forms.CheckBox();
            this.checkBoxDigitalSignature = new System.Windows.Forms.CheckBox();
            this.groupBoxBasicConstraints = new System.Windows.Forms.GroupBox();
            this.textBoxPathLen = new System.Windows.Forms.TextBox();
            this.checkBoxPathLen = new System.Windows.Forms.CheckBox();
            this.checkBoxCA = new System.Windows.Forms.CheckBox();
            this.groupBoxExtKeyUsage = new System.Windows.Forms.GroupBox();
            this.checkBoxAnyExtKeyUsage = new System.Windows.Forms.CheckBox();
            this.checkBoxOCSPSigning = new System.Windows.Forms.CheckBox();
            this.checkBoxTimeStamping = new System.Windows.Forms.CheckBox();
            this.checkBoxEmailProtection = new System.Windows.Forms.CheckBox();
            this.checkBoxCodeSigning = new System.Windows.Forms.CheckBox();
            this.checkBoxClientAuth = new System.Windows.Forms.CheckBox();
            this.checkBoxServerAuth = new System.Windows.Forms.CheckBox();
            this.groupBoxKeyUsage.SuspendLayout();
            this.groupBoxBasicConstraints.SuspendLayout();
            this.groupBoxExtKeyUsage.SuspendLayout();
            this.SuspendLayout();
            // 
            // labelSubject
            // 
            resources.ApplyResources(this.labelSubject, "labelSubject");
            this.labelSubject.Name = "labelSubject";
            // 
            // textBoxSubject
            // 
            resources.ApplyResources(this.textBoxSubject, "textBoxSubject");
            this.textBoxSubject.Name = "textBoxSubject";
            this.textBoxSubject.Validating += new System.ComponentModel.CancelEventHandler(this.OnSubjectValidating);
            // 
            // buttonOK
            // 
            resources.ApplyResources(this.buttonOK, "buttonOK");
            this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.UseVisualStyleBackColor = true;
            // 
            // buttonCancel
            // 
            resources.ApplyResources(this.buttonCancel, "buttonCancel");
            this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.buttonCancel.Name = "buttonCancel";
            this.buttonCancel.UseVisualStyleBackColor = true;
            // 
            // labelFrom
            // 
            resources.ApplyResources(this.labelFrom, "labelFrom");
            this.labelFrom.Name = "labelFrom";
            // 
            // labelBefore
            // 
            resources.ApplyResources(this.labelBefore, "labelBefore");
            this.labelBefore.Name = "labelBefore";
            // 
            // dateTimeFrom
            // 
            resources.ApplyResources(this.dateTimeFrom, "dateTimeFrom");
            this.dateTimeFrom.Name = "dateTimeFrom";
            // 
            // dateTimeBefore
            // 
            resources.ApplyResources(this.dateTimeBefore, "dateTimeBefore");
            this.dateTimeBefore.Name = "dateTimeBefore";
            // 
            // groupBoxKeyUsage
            // 
            resources.ApplyResources(this.groupBoxKeyUsage, "groupBoxKeyUsage");
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxDecipherOnly);
            this.groupBoxKeyUsage.Controls.Add(this.checkBoxEncipherOnly);
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
            // checkBoxDecipherOnly
            // 
            resources.ApplyResources(this.checkBoxDecipherOnly, "checkBoxDecipherOnly");
            this.checkBoxDecipherOnly.Name = "checkBoxDecipherOnly";
            this.checkBoxDecipherOnly.UseVisualStyleBackColor = true;
            this.checkBoxDecipherOnly.CheckedChanged += new System.EventHandler(this.OnDecipherOnlyCheckChanged);
            // 
            // checkBoxEncipherOnly
            // 
            resources.ApplyResources(this.checkBoxEncipherOnly, "checkBoxEncipherOnly");
            this.checkBoxEncipherOnly.Name = "checkBoxEncipherOnly";
            this.checkBoxEncipherOnly.UseVisualStyleBackColor = true;
            this.checkBoxEncipherOnly.CheckedChanged += new System.EventHandler(this.OnEncipherOnlyCheckChanged);
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
            this.checkBoxKeyAgreement.CheckedChanged += new System.EventHandler(this.OnKeyAgreementCheckChanged);
            // 
            // checkBoxKeyEncipherment
            // 
            resources.ApplyResources(this.checkBoxKeyEncipherment, "checkBoxKeyEncipherment");
            this.checkBoxKeyEncipherment.Name = "checkBoxKeyEncipherment";
            this.checkBoxKeyEncipherment.UseVisualStyleBackColor = true;
            this.checkBoxKeyEncipherment.CheckedChanged += new System.EventHandler(this.OnKeyEnciphermentCheckedChanged);
            // 
            // checkBoxNonRepudiation
            // 
            resources.ApplyResources(this.checkBoxNonRepudiation, "checkBoxNonRepudiation");
            this.checkBoxNonRepudiation.Name = "checkBoxNonRepudiation";
            this.checkBoxNonRepudiation.UseVisualStyleBackColor = true;
            this.checkBoxNonRepudiation.CheckedChanged += new System.EventHandler(this.OnNonRepudiationCheckChanged);
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
            this.checkBoxDigitalSignature.CheckedChanged += new System.EventHandler(this.OnDigitalSignatureCheckChanged);
            // 
            // groupBoxBasicConstraints
            // 
            resources.ApplyResources(this.groupBoxBasicConstraints, "groupBoxBasicConstraints");
            this.groupBoxBasicConstraints.Controls.Add(this.textBoxPathLen);
            this.groupBoxBasicConstraints.Controls.Add(this.checkBoxPathLen);
            this.groupBoxBasicConstraints.Controls.Add(this.checkBoxCA);
            this.groupBoxBasicConstraints.Name = "groupBoxBasicConstraints";
            this.groupBoxBasicConstraints.TabStop = false;
            // 
            // textBoxPathLen
            // 
            resources.ApplyResources(this.textBoxPathLen, "textBoxPathLen");
            this.textBoxPathLen.Name = "textBoxPathLen";
            this.textBoxPathLen.Validating += new System.ComponentModel.CancelEventHandler(this.OnPathLenValidating);
            // 
            // checkBoxPathLen
            // 
            resources.ApplyResources(this.checkBoxPathLen, "checkBoxPathLen");
            this.checkBoxPathLen.Name = "checkBoxPathLen";
            this.checkBoxPathLen.UseVisualStyleBackColor = true;
            this.checkBoxPathLen.CheckedChanged += new System.EventHandler(this.OnPathLenCheckedChanged);
            // 
            // checkBoxCA
            // 
            resources.ApplyResources(this.checkBoxCA, "checkBoxCA");
            this.checkBoxCA.Name = "checkBoxCA";
            this.checkBoxCA.UseVisualStyleBackColor = true;
            this.checkBoxCA.CheckedChanged += new System.EventHandler(this.OnCACheckedChanged);
            // 
            // groupBoxExtKeyUsage
            // 
            resources.ApplyResources(this.groupBoxExtKeyUsage, "groupBoxExtKeyUsage");
            this.groupBoxExtKeyUsage.Controls.Add(this.checkBoxAnyExtKeyUsage);
            this.groupBoxExtKeyUsage.Controls.Add(this.checkBoxOCSPSigning);
            this.groupBoxExtKeyUsage.Controls.Add(this.checkBoxTimeStamping);
            this.groupBoxExtKeyUsage.Controls.Add(this.checkBoxEmailProtection);
            this.groupBoxExtKeyUsage.Controls.Add(this.checkBoxCodeSigning);
            this.groupBoxExtKeyUsage.Controls.Add(this.checkBoxClientAuth);
            this.groupBoxExtKeyUsage.Controls.Add(this.checkBoxServerAuth);
            this.groupBoxExtKeyUsage.Name = "groupBoxExtKeyUsage";
            this.groupBoxExtKeyUsage.TabStop = false;
            // 
            // checkBoxAnyExtKeyUsage
            // 
            resources.ApplyResources(this.checkBoxAnyExtKeyUsage, "checkBoxAnyExtKeyUsage");
            this.checkBoxAnyExtKeyUsage.Name = "checkBoxAnyExtKeyUsage";
            this.checkBoxAnyExtKeyUsage.UseVisualStyleBackColor = true;
            // 
            // checkBoxOCSPSigning
            // 
            resources.ApplyResources(this.checkBoxOCSPSigning, "checkBoxOCSPSigning");
            this.checkBoxOCSPSigning.Name = "checkBoxOCSPSigning";
            this.checkBoxOCSPSigning.UseVisualStyleBackColor = true;
            // 
            // checkBoxTimeStamping
            // 
            resources.ApplyResources(this.checkBoxTimeStamping, "checkBoxTimeStamping");
            this.checkBoxTimeStamping.Name = "checkBoxTimeStamping";
            this.checkBoxTimeStamping.UseVisualStyleBackColor = true;
            // 
            // checkBoxEmailProtection
            // 
            resources.ApplyResources(this.checkBoxEmailProtection, "checkBoxEmailProtection");
            this.checkBoxEmailProtection.Name = "checkBoxEmailProtection";
            this.checkBoxEmailProtection.UseVisualStyleBackColor = true;
            // 
            // checkBoxCodeSigning
            // 
            resources.ApplyResources(this.checkBoxCodeSigning, "checkBoxCodeSigning");
            this.checkBoxCodeSigning.Name = "checkBoxCodeSigning";
            this.checkBoxCodeSigning.UseVisualStyleBackColor = true;
            // 
            // checkBoxClientAuth
            // 
            resources.ApplyResources(this.checkBoxClientAuth, "checkBoxClientAuth");
            this.checkBoxClientAuth.Name = "checkBoxClientAuth";
            this.checkBoxClientAuth.UseVisualStyleBackColor = true;
            // 
            // checkBoxServerAuth
            // 
            resources.ApplyResources(this.checkBoxServerAuth, "checkBoxServerAuth");
            this.checkBoxServerAuth.Name = "checkBoxServerAuth";
            this.checkBoxServerAuth.UseVisualStyleBackColor = true;
            // 
            // CertRequestDialog
            // 
            this.AcceptButton = this.buttonOK;
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.buttonCancel;
            this.Controls.Add(this.groupBoxExtKeyUsage);
            this.Controls.Add(this.groupBoxBasicConstraints);
            this.Controls.Add(this.groupBoxKeyUsage);
            this.Controls.Add(this.dateTimeBefore);
            this.Controls.Add(this.dateTimeFrom);
            this.Controls.Add(this.labelBefore);
            this.Controls.Add(this.labelFrom);
            this.Controls.Add(this.buttonCancel);
            this.Controls.Add(this.buttonOK);
            this.Controls.Add(this.textBoxSubject);
            this.Controls.Add(this.labelSubject);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "CertRequestDialog";
            this.groupBoxKeyUsage.ResumeLayout(false);
            this.groupBoxKeyUsage.PerformLayout();
            this.groupBoxBasicConstraints.ResumeLayout(false);
            this.groupBoxBasicConstraints.PerformLayout();
            this.groupBoxExtKeyUsage.ResumeLayout(false);
            this.groupBoxExtKeyUsage.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

		}

		#endregion

        private System.Windows.Forms.Label labelSubject;
        private System.Windows.Forms.TextBox textBoxSubject;
		private System.Windows.Forms.Button buttonOK;
        private System.Windows.Forms.Button buttonCancel;
		private System.Windows.Forms.Label labelFrom;
		private System.Windows.Forms.Label labelBefore;
		private System.Windows.Forms.DateTimePicker dateTimeFrom;
        private System.Windows.Forms.DateTimePicker dateTimeBefore;
        private System.Windows.Forms.GroupBox groupBoxKeyUsage;
        private System.Windows.Forms.CheckBox checkBoxDecipherOnly;
        private System.Windows.Forms.CheckBox checkBoxEncipherOnly;
        private System.Windows.Forms.CheckBox checkBoxDataEncipherment;
        private System.Windows.Forms.CheckBox checkBoxKeyAgreement;
        private System.Windows.Forms.CheckBox checkBoxKeyEncipherment;
        private System.Windows.Forms.CheckBox checkBoxNonRepudiation;
        private System.Windows.Forms.CheckBox checkBoxCrlSignature;
        private System.Windows.Forms.CheckBox checkBoxCertificateSignature;
        private System.Windows.Forms.CheckBox checkBoxDigitalSignature;
        private System.Windows.Forms.GroupBox groupBoxBasicConstraints;
        private System.Windows.Forms.TextBox textBoxPathLen;
        private System.Windows.Forms.CheckBox checkBoxPathLen;
        private System.Windows.Forms.CheckBox checkBoxCA;
        private System.Windows.Forms.GroupBox groupBoxExtKeyUsage;
        private System.Windows.Forms.CheckBox checkBoxAnyExtKeyUsage;
        private System.Windows.Forms.CheckBox checkBoxOCSPSigning;
        private System.Windows.Forms.CheckBox checkBoxTimeStamping;
        private System.Windows.Forms.CheckBox checkBoxEmailProtection;
        private System.Windows.Forms.CheckBox checkBoxCodeSigning;
        private System.Windows.Forms.CheckBox checkBoxClientAuth;
        private System.Windows.Forms.CheckBox checkBoxServerAuth;
	}
}