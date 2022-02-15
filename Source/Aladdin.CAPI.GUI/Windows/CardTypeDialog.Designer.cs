namespace Aladdin.CAPI.GUI
{
	partial class CardTypeDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(CardTypeDialog));
            this.buttonOK = new System.Windows.Forms.Button();
            this.groupBoxReader = new System.Windows.Forms.GroupBox();
            this.textBoxKSP = new System.Windows.Forms.TextBox();
            this.textBoxPrimary = new System.Windows.Forms.TextBox();
            this.textBoxCSP = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
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
            this.groupBoxReader.Controls.Add(this.textBoxKSP);
            this.groupBoxReader.Controls.Add(this.textBoxPrimary);
            this.groupBoxReader.Controls.Add(this.textBoxCSP);
            this.groupBoxReader.Controls.Add(this.label4);
            this.groupBoxReader.Controls.Add(this.label3);
            this.groupBoxReader.Controls.Add(this.label1);
            this.groupBoxReader.Name = "groupBoxReader";
            this.groupBoxReader.TabStop = false;
            // 
            // textBoxKSP
            // 
            resources.ApplyResources(this.textBoxKSP, "textBoxKSP");
            this.textBoxKSP.Name = "textBoxKSP";
            this.textBoxKSP.ReadOnly = true;
            // 
            // textBoxPrimary
            // 
            resources.ApplyResources(this.textBoxPrimary, "textBoxPrimary");
            this.textBoxPrimary.Name = "textBoxPrimary";
            this.textBoxPrimary.ReadOnly = true;
            // 
            // textBoxCSP
            // 
            resources.ApplyResources(this.textBoxCSP, "textBoxCSP");
            this.textBoxCSP.Name = "textBoxCSP";
            this.textBoxCSP.ReadOnly = true;
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
            // label1
            // 
            resources.ApplyResources(this.label1, "label1");
            this.label1.Name = "label1";
            // 
            // CardTypeDialog
            // 
            this.AcceptButton = this.buttonOK;
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.groupBoxReader);
            this.Controls.Add(this.buttonOK);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "CardTypeDialog";
            this.groupBoxReader.ResumeLayout(false);
            this.groupBoxReader.PerformLayout();
            this.ResumeLayout(false);

		}

		#endregion

        private System.Windows.Forms.Button buttonOK;
        private System.Windows.Forms.GroupBox groupBoxReader;
        private System.Windows.Forms.TextBox textBoxKSP;
        private System.Windows.Forms.TextBox textBoxPrimary;
        private System.Windows.Forms.TextBox textBoxCSP;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label1;

	}
}