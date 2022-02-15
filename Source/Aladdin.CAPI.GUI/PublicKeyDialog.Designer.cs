namespace Aladdin.CAPI.GUI
{
	partial class PublicKeyDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(PublicKeyDialog));
            this.buttonOK = new System.Windows.Forms.Button();
            this.tabPageGeneral = new System.Windows.Forms.TabPage();
            this.textBoxBase64 = new System.Windows.Forms.TextBox();
            this.textBoxValue = new System.Windows.Forms.TextBox();
            this.textBoxOID = new System.Windows.Forms.TextBox();
            this.labelBase64 = new System.Windows.Forms.Label();
            this.labelValue = new System.Windows.Forms.Label();
            this.labelOID = new System.Windows.Forms.Label();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabPageGeneral.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.SuspendLayout();
            // 
            // buttonOK
            // 
            resources.ApplyResources(this.buttonOK, "buttonOK");
            this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.UseVisualStyleBackColor = true;
            // 
            // tabPageGeneral
            // 
            this.tabPageGeneral.Controls.Add(this.textBoxBase64);
            this.tabPageGeneral.Controls.Add(this.textBoxValue);
            this.tabPageGeneral.Controls.Add(this.textBoxOID);
            this.tabPageGeneral.Controls.Add(this.labelBase64);
            this.tabPageGeneral.Controls.Add(this.labelValue);
            this.tabPageGeneral.Controls.Add(this.labelOID);
            resources.ApplyResources(this.tabPageGeneral, "tabPageGeneral");
            this.tabPageGeneral.Name = "tabPageGeneral";
            this.tabPageGeneral.UseVisualStyleBackColor = true;
            // 
            // textBoxBase64
            // 
            resources.ApplyResources(this.textBoxBase64, "textBoxBase64");
            this.textBoxBase64.Name = "textBoxBase64";
            this.textBoxBase64.ReadOnly = true;
            // 
            // textBoxValue
            // 
            resources.ApplyResources(this.textBoxValue, "textBoxValue");
            this.textBoxValue.Name = "textBoxValue";
            this.textBoxValue.ReadOnly = true;
            // 
            // textBoxOID
            // 
            resources.ApplyResources(this.textBoxOID, "textBoxOID");
            this.textBoxOID.Name = "textBoxOID";
            this.textBoxOID.ReadOnly = true;
            // 
            // labelBase64
            // 
            resources.ApplyResources(this.labelBase64, "labelBase64");
            this.labelBase64.Name = "labelBase64";
            // 
            // labelValue
            // 
            resources.ApplyResources(this.labelValue, "labelValue");
            this.labelValue.Name = "labelValue";
            // 
            // labelOID
            // 
            resources.ApplyResources(this.labelOID, "labelOID");
            this.labelOID.Name = "labelOID";
            // 
            // tabControl
            // 
            resources.ApplyResources(this.tabControl, "tabControl");
            this.tabControl.Controls.Add(this.tabPageGeneral);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            // 
            // PublicKeyDialog
            // 
            this.AcceptButton = this.buttonOK;
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.tabControl);
            this.Controls.Add(this.buttonOK);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "PublicKeyDialog";
            this.Load += new System.EventHandler(this.OnLoad);
            this.tabPageGeneral.ResumeLayout(false);
            this.tabPageGeneral.PerformLayout();
            this.tabControl.ResumeLayout(false);
            this.ResumeLayout(false);

		}

		#endregion

        private System.Windows.Forms.Button buttonOK;
        private System.Windows.Forms.TabPage tabPageGeneral;
        private System.Windows.Forms.TextBox textBoxBase64;
        private System.Windows.Forms.TextBox textBoxValue;
        private System.Windows.Forms.TextBox textBoxOID;
        private System.Windows.Forms.Label labelBase64;
        private System.Windows.Forms.Label labelValue;
        private System.Windows.Forms.Label labelOID;
        private System.Windows.Forms.TabControl tabControl;

	}
}