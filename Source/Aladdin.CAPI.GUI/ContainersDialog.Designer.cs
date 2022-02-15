namespace Aladdin.CAPI.GUI
{
	partial class ContainersDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ContainersDialog));
            this.buttonCancel = new System.Windows.Forms.Button();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabTemplate = new System.Windows.Forms.TabPage();
            this.containersView = new Aladdin.CAPI.GUI.ContainersView();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.label = new System.Windows.Forms.Label();
            this.checkSystem = new System.Windows.Forms.CheckBox();
            this.buttonOK = new System.Windows.Forms.Button();
            this.tabControl.SuspendLayout();
            this.tabTemplate.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // buttonCancel
            // 
            resources.ApplyResources(this.buttonCancel, "buttonCancel");
            this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.buttonCancel.Name = "buttonCancel";
            this.buttonCancel.UseVisualStyleBackColor = true;
            // 
            // tabControl
            // 
            resources.ApplyResources(this.tabControl, "tabControl");
            this.tabControl.Controls.Add(this.tabTemplate);
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            this.tabControl.SelectedIndexChanged += new System.EventHandler(this.OnTabControlChanged);
            // 
            // tabTemplate
            // 
            this.tabTemplate.Controls.Add(this.containersView);
            resources.ApplyResources(this.tabTemplate, "tabTemplate");
            this.tabTemplate.Name = "tabTemplate";
            this.tabTemplate.UseVisualStyleBackColor = true;
            // 
            // containersView
            // 
            resources.ApplyResources(this.containersView, "containersView");
            this.containersView.Name = "containersView";
            // 
            // pictureBox1
            // 
            resources.ApplyResources(this.pictureBox1, "pictureBox1");
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.TabStop = false;
            // 
            // label
            // 
            resources.ApplyResources(this.label, "label");
            this.label.BackColor = System.Drawing.SystemColors.Window;
            this.label.Name = "label";
            // 
            // checkSystem
            // 
            resources.ApplyResources(this.checkSystem, "checkSystem");
            this.checkSystem.Name = "checkSystem";
            this.checkSystem.UseVisualStyleBackColor = true;
            this.checkSystem.CheckedChanged += new System.EventHandler(this.OnScopeChanged);
            // 
            // buttonOK
            // 
            resources.ApplyResources(this.buttonOK, "buttonOK");
            this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.UseVisualStyleBackColor = true;
            this.buttonOK.Click += new System.EventHandler(this.OnClickOK);
            // 
            // ContainersDialog
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.buttonOK);
            this.Controls.Add(this.checkSystem);
            this.Controls.Add(this.label);
            this.Controls.Add(this.pictureBox1);
            this.Controls.Add(this.tabControl);
            this.Controls.Add(this.buttonCancel);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MinimizeBox = false;
            this.Name = "ContainersDialog";
            this.tabControl.ResumeLayout(false);
            this.tabTemplate.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

		}

		#endregion

		private System.Windows.Forms.Button buttonCancel; 
		private System.Windows.Forms.TabControl tabControl;
		private System.Windows.Forms.TabPage tabTemplate;
		private Aladdin.CAPI.GUI.ContainersView containersView;
		private System.Windows.Forms.PictureBox pictureBox1;
		private System.Windows.Forms.Label label;
		private System.Windows.Forms.CheckBox checkSystem;
		private System.Windows.Forms.Button buttonOK;
	}
}