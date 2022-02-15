namespace Aladdin.CAPI.STB.GUI
{
    partial class KeyControl34101
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

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(KeyControl34101));
            this.groupBox = new System.Windows.Forms.GroupBox();
            this.radio512 = new System.Windows.Forms.RadioButton();
            this.radio384 = new System.Windows.Forms.RadioButton();
            this.radio256 = new System.Windows.Forms.RadioButton();
            this.groupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox
            // 
            this.groupBox.Controls.Add(this.radio512);
            this.groupBox.Controls.Add(this.radio384);
            this.groupBox.Controls.Add(this.radio256);
            resources.ApplyResources(this.groupBox, "groupBox");
            this.groupBox.Name = "groupBox";
            this.groupBox.TabStop = false;
            // 
            // radio512
            // 
            resources.ApplyResources(this.radio512, "radio512");
            this.radio512.Name = "radio512";
            this.radio512.UseVisualStyleBackColor = true;
            // 
            // radio384
            // 
            resources.ApplyResources(this.radio384, "radio384");
            this.radio384.Name = "radio384";
            this.radio384.UseVisualStyleBackColor = true;
            // 
            // radio256
            // 
            resources.ApplyResources(this.radio256, "radio256");
            this.radio256.Checked = true;
            this.radio256.Name = "radio256";
            this.radio256.TabStop = true;
            this.radio256.UseVisualStyleBackColor = true;
            // 
            // KeyControl34101
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.groupBox);
            this.Name = "KeyControl34101";
            this.groupBox.ResumeLayout(false);
            this.groupBox.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox;
        private System.Windows.Forms.RadioButton radio512;
        private System.Windows.Forms.RadioButton radio384;
        private System.Windows.Forms.RadioButton radio256;

    }
}
