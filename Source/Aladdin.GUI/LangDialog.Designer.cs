namespace Aladdin.GUI
{
	partial class LangDialog
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
			System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(LangDialog));
			this.englishButton = new System.Windows.Forms.RadioButton();
			this.russianButton = new System.Windows.Forms.RadioButton();
			this.buttonOK = new System.Windows.Forms.Button();
			this.buttonCancel = new System.Windows.Forms.Button();
			this.groupBox = new System.Windows.Forms.GroupBox();
			this.groupBox.SuspendLayout();
			this.SuspendLayout();
			// 
			// englishButton
			// 
			this.englishButton.AccessibleDescription = null;
			this.englishButton.AccessibleName = null;
			resources.ApplyResources(this.englishButton, "englishButton");
			this.englishButton.BackgroundImage = null;
			this.englishButton.Checked = true;
			this.englishButton.Font = null;
			this.englishButton.Name = "englishButton";
			this.englishButton.TabStop = true;
			this.englishButton.UseVisualStyleBackColor = true;
			// 
			// russianButton
			// 
			this.russianButton.AccessibleDescription = null;
			this.russianButton.AccessibleName = null;
			resources.ApplyResources(this.russianButton, "russianButton");
			this.russianButton.BackgroundImage = null;
			this.russianButton.Font = null;
			this.russianButton.Name = "russianButton";
			this.russianButton.UseVisualStyleBackColor = true;
			// 
			// buttonOK
			// 
			this.buttonOK.AccessibleDescription = null;
			this.buttonOK.AccessibleName = null;
			resources.ApplyResources(this.buttonOK, "buttonOK");
			this.buttonOK.BackgroundImage = null;
			this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
			this.buttonOK.Font = null;
			this.buttonOK.Name = "buttonOK";
			this.buttonOK.UseVisualStyleBackColor = true;
			// 
			// buttonCancel
			// 
			this.buttonCancel.AccessibleDescription = null;
			this.buttonCancel.AccessibleName = null;
			resources.ApplyResources(this.buttonCancel, "buttonCancel");
			this.buttonCancel.BackgroundImage = null;
			this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
			this.buttonCancel.Font = null;
			this.buttonCancel.Name = "buttonCancel";
			this.buttonCancel.UseVisualStyleBackColor = true;
			// 
			// groupBox
			// 
			this.groupBox.AccessibleDescription = null;
			this.groupBox.AccessibleName = null;
			resources.ApplyResources(this.groupBox, "groupBox");
			this.groupBox.BackgroundImage = null;
			this.groupBox.Controls.Add(this.englishButton);
			this.groupBox.Controls.Add(this.russianButton);
			this.groupBox.Font = null;
			this.groupBox.Name = "groupBox";
			this.groupBox.TabStop = false;
			// 
			// LangDialog
			// 
			this.AccessibleDescription = null;
			this.AccessibleName = null;
			resources.ApplyResources(this, "$this");
			this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
			this.BackgroundImage = null;
			this.Controls.Add(this.groupBox);
			this.Controls.Add(this.buttonCancel);
			this.Controls.Add(this.buttonOK);
			this.Font = null;
			this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
			this.MaximizeBox = false;
			this.MinimizeBox = false;
			this.Name = "LangDialog";
			this.groupBox.ResumeLayout(false);
			this.groupBox.PerformLayout();
			this.ResumeLayout(false);

		}

		#endregion

		private System.Windows.Forms.RadioButton englishButton;
		private System.Windows.Forms.RadioButton russianButton;
		private System.Windows.Forms.Button buttonOK;
		private System.Windows.Forms.Button buttonCancel;
		private System.Windows.Forms.GroupBox groupBox;

	}
}