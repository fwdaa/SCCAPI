namespace Aladdin.CAPI.GUI
{
	partial class AuthenticationDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(AuthenticationDialog));
            this.textBoxContainer = new System.Windows.Forms.TextBox();
            this.labelContainer = new System.Windows.Forms.Label();
            this.buttonOK = new System.Windows.Forms.Button();
            this.buttonCancel = new System.Windows.Forms.Button();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.label1 = new System.Windows.Forms.Label();
            this.labelProvider = new System.Windows.Forms.Label();
            this.textBoxProvider = new System.Windows.Forms.TextBox();
            this.labelType = new System.Windows.Forms.Label();
            this.comboBoxUser = new System.Windows.Forms.ComboBox();
            this.groupBoxType = new System.Windows.Forms.GroupBox();
            this.checkBoxBiometric = new System.Windows.Forms.CheckBox();
            this.checkBoxPassword = new System.Windows.Forms.CheckBox();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.groupBoxType.SuspendLayout();
            this.SuspendLayout();
            // 
            // textBoxContainer
            // 
            resources.ApplyResources(this.textBoxContainer, "textBoxContainer");
            this.textBoxContainer.Name = "textBoxContainer";
            this.textBoxContainer.ReadOnly = true;
            // 
            // labelContainer
            // 
            resources.ApplyResources(this.labelContainer, "labelContainer");
            this.labelContainer.Name = "labelContainer";
            // 
            // buttonOK
            // 
            resources.ApplyResources(this.buttonOK, "buttonOK");
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.UseVisualStyleBackColor = true;
            this.buttonOK.Click += new System.EventHandler(this.OnButtonOK);
            // 
            // buttonCancel
            // 
            resources.ApplyResources(this.buttonCancel, "buttonCancel");
            this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.buttonCancel.Name = "buttonCancel";
            this.buttonCancel.UseVisualStyleBackColor = true;
            // 
            // pictureBox1
            // 
            resources.ApplyResources(this.pictureBox1, "pictureBox1");
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.TabStop = false;
            // 
            // label1
            // 
            resources.ApplyResources(this.label1, "label1");
            this.label1.BackColor = System.Drawing.Color.White;
            this.label1.Name = "label1";
            // 
            // labelProvider
            // 
            resources.ApplyResources(this.labelProvider, "labelProvider");
            this.labelProvider.Name = "labelProvider";
            // 
            // textBoxProvider
            // 
            resources.ApplyResources(this.textBoxProvider, "textBoxProvider");
            this.textBoxProvider.Name = "textBoxProvider";
            this.textBoxProvider.ReadOnly = true;
            // 
            // labelType
            // 
            resources.ApplyResources(this.labelType, "labelType");
            this.labelType.Name = "labelType";
            // 
            // comboBoxUser
            // 
            resources.ApplyResources(this.comboBoxUser, "comboBoxUser");
            this.comboBoxUser.FormattingEnabled = true;
            this.comboBoxUser.Items.AddRange(new object[] {
            resources.GetString("comboBoxUser.Items"),
            resources.GetString("comboBoxUser.Items1")});
            this.comboBoxUser.Name = "comboBoxUser";
            this.comboBoxUser.SelectedIndexChanged += new System.EventHandler(this.OnUserTypeChanged);
            // 
            // groupBoxType
            // 
            resources.ApplyResources(this.groupBoxType, "groupBoxType");
            this.groupBoxType.Controls.Add(this.checkBoxBiometric);
            this.groupBoxType.Controls.Add(this.checkBoxPassword);
            this.groupBoxType.Name = "groupBoxType";
            this.groupBoxType.TabStop = false;
            // 
            // checkBoxBiometric
            // 
            resources.ApplyResources(this.checkBoxBiometric, "checkBoxBiometric");
            this.checkBoxBiometric.Name = "checkBoxBiometric";
            this.checkBoxBiometric.UseVisualStyleBackColor = true;
            this.checkBoxBiometric.CheckedChanged += new System.EventHandler(this.OnAuthenticationChanged);
            // 
            // checkBoxPassword
            // 
            resources.ApplyResources(this.checkBoxPassword, "checkBoxPassword");
            this.checkBoxPassword.Name = "checkBoxPassword";
            this.checkBoxPassword.UseVisualStyleBackColor = true;
            this.checkBoxPassword.CheckedChanged += new System.EventHandler(this.OnAuthenticationChanged);
            // 
            // AuthenticationDialog
            // 
            this.AcceptButton = this.buttonOK;
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.buttonCancel;
            this.Controls.Add(this.groupBoxType);
            this.Controls.Add(this.comboBoxUser);
            this.Controls.Add(this.labelType);
            this.Controls.Add(this.labelProvider);
            this.Controls.Add(this.textBoxProvider);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.pictureBox1);
            this.Controls.Add(this.buttonCancel);
            this.Controls.Add(this.buttonOK);
            this.Controls.Add(this.labelContainer);
            this.Controls.Add(this.textBoxContainer);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "AuthenticationDialog";
            this.TopMost = true;
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.groupBoxType.ResumeLayout(false);
            this.groupBoxType.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

		}

		#endregion

        private System.Windows.Forms.TextBox textBoxContainer;
        private System.Windows.Forms.Label labelContainer;
		private System.Windows.Forms.Button buttonOK;
        private System.Windows.Forms.Button buttonCancel;
		private System.Windows.Forms.PictureBox pictureBox1;
		private System.Windows.Forms.Label label1;
		private System.Windows.Forms.Label labelProvider;
		private System.Windows.Forms.TextBox textBoxProvider;
        private System.Windows.Forms.Label labelType;
        private System.Windows.Forms.ComboBox comboBoxUser;
        private System.Windows.Forms.GroupBox groupBoxType;
        private System.Windows.Forms.CheckBox checkBoxBiometric;
        private System.Windows.Forms.CheckBox checkBoxPassword;
	}
}