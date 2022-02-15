namespace Aladdin.CAPI.GUI
{
	partial class ReaderDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ReaderDialog));
            this.buttonOK = new System.Windows.Forms.Button();
            this.groupBoxReader = new System.Windows.Forms.GroupBox();
            this.textBoxInfo = new System.Windows.Forms.TextBox();
            this.textBoxFV = new System.Windows.Forms.TextBox();
            this.textBoxHV = new System.Windows.Forms.TextBox();
            this.textBoxVendor = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.groupBoxReader.SuspendLayout();
            this.SuspendLayout();
            // 
            // buttonOK
            // 
            resources.ApplyResources(this.buttonOK, "buttonOK");
            this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.UseVisualStyleBackColor = true;
            // 
            // groupBoxReader
            // 
            resources.ApplyResources(this.groupBoxReader, "groupBoxReader");
            this.groupBoxReader.Controls.Add(this.textBoxInfo);
            this.groupBoxReader.Controls.Add(this.textBoxFV);
            this.groupBoxReader.Controls.Add(this.textBoxHV);
            this.groupBoxReader.Controls.Add(this.textBoxVendor);
            this.groupBoxReader.Controls.Add(this.label4);
            this.groupBoxReader.Controls.Add(this.label3);
            this.groupBoxReader.Controls.Add(this.label2);
            this.groupBoxReader.Controls.Add(this.label1);
            this.groupBoxReader.Name = "groupBoxReader";
            this.groupBoxReader.TabStop = false;
            // 
            // textBoxInfo
            // 
            resources.ApplyResources(this.textBoxInfo, "textBoxInfo");
            this.textBoxInfo.Name = "textBoxInfo";
            this.textBoxInfo.ReadOnly = true;
            // 
            // textBoxFV
            // 
            resources.ApplyResources(this.textBoxFV, "textBoxFV");
            this.textBoxFV.Name = "textBoxFV";
            this.textBoxFV.ReadOnly = true;
            // 
            // textBoxHV
            // 
            resources.ApplyResources(this.textBoxHV, "textBoxHV");
            this.textBoxHV.Name = "textBoxHV";
            this.textBoxHV.ReadOnly = true;
            // 
            // textBoxVendor
            // 
            resources.ApplyResources(this.textBoxVendor, "textBoxVendor");
            this.textBoxVendor.Name = "textBoxVendor";
            this.textBoxVendor.ReadOnly = true;
            // 
            // label4
            // 
            resources.ApplyResources(this.label4, "label4");
            this.label4.Name = "label4";
            // 
            // label3
            // 
            resources.ApplyResources(this.label3, "label3");
            this.label3.Name = "label3";
            // 
            // label2
            // 
            resources.ApplyResources(this.label2, "label2");
            this.label2.Name = "label2";
            // 
            // label1
            // 
            resources.ApplyResources(this.label1, "label1");
            this.label1.Name = "label1";
            // 
            // ReaderDialog
            // 
            this.AcceptButton = this.buttonOK;
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.groupBoxReader);
            this.Controls.Add(this.buttonOK);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "ReaderDialog";
            this.groupBoxReader.ResumeLayout(false);
            this.groupBoxReader.PerformLayout();
            this.ResumeLayout(false);

		}

		#endregion

        private System.Windows.Forms.Button buttonOK;
        private System.Windows.Forms.GroupBox groupBoxReader;
        private System.Windows.Forms.TextBox textBoxInfo;
        private System.Windows.Forms.TextBox textBoxFV;
        private System.Windows.Forms.TextBox textBoxHV;
        private System.Windows.Forms.TextBox textBoxVendor;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;

	}
}