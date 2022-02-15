namespace Aladdin.CAPI.ANSI.GUI
{
    partial class RSAControl
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(RSAControl));
            this.groupBox = new System.Windows.Forms.GroupBox();
            this.radio4096 = new System.Windows.Forms.RadioButton();
            this.radio3072 = new System.Windows.Forms.RadioButton();
            this.radio2048 = new System.Windows.Forms.RadioButton();
            this.radio1536 = new System.Windows.Forms.RadioButton();
            this.radio1024 = new System.Windows.Forms.RadioButton();
            this.radio512 = new System.Windows.Forms.RadioButton();
            this.groupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox
            // 
            this.groupBox.Controls.Add(this.radio4096);
            this.groupBox.Controls.Add(this.radio3072);
            this.groupBox.Controls.Add(this.radio2048);
            this.groupBox.Controls.Add(this.radio1536);
            this.groupBox.Controls.Add(this.radio1024);
            this.groupBox.Controls.Add(this.radio512);
            resources.ApplyResources(this.groupBox, "groupBox");
            this.groupBox.Name = "groupBox";
            this.groupBox.TabStop = false;
            // 
            // radio4096
            // 
            resources.ApplyResources(this.radio4096, "radio4096");
            this.radio4096.Name = "radio4096";
            this.radio4096.UseVisualStyleBackColor = true;
            // 
            // radio3072
            // 
            resources.ApplyResources(this.radio3072, "radio3072");
            this.radio3072.Name = "radio3072";
            this.radio3072.UseVisualStyleBackColor = true;
            // 
            // radio2048
            // 
            resources.ApplyResources(this.radio2048, "radio2048");
            this.radio2048.Name = "radio2048";
            this.radio2048.UseVisualStyleBackColor = true;
            // 
            // radio1536
            // 
            resources.ApplyResources(this.radio1536, "radio1536");
            this.radio1536.Name = "radio1536";
            this.radio1536.UseVisualStyleBackColor = true;
            // 
            // radio1024
            // 
            resources.ApplyResources(this.radio1024, "radio1024");
            this.radio1024.Checked = true;
            this.radio1024.Name = "radio1024";
            this.radio1024.TabStop = true;
            this.radio1024.UseVisualStyleBackColor = true;
            // 
            // radio512
            // 
            resources.ApplyResources(this.radio512, "radio512");
            this.radio512.Name = "radio512";
            this.radio512.UseVisualStyleBackColor = true;
            // 
            // RSAControl
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.groupBox);
            this.Name = "RSAControl";
            this.groupBox.ResumeLayout(false);
            this.groupBox.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox;
        private System.Windows.Forms.RadioButton radio4096;
        private System.Windows.Forms.RadioButton radio3072;
        private System.Windows.Forms.RadioButton radio2048;
        private System.Windows.Forms.RadioButton radio1536;
        private System.Windows.Forms.RadioButton radio1024;
        private System.Windows.Forms.RadioButton radio512;
    }
}
