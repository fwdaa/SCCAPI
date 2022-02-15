namespace Aladdin.CAPI.GOST.GUI
{
    partial class KeyControl2012_256X
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(KeyControl2012_256X));
            this.groupBoxEC = new System.Windows.Forms.GroupBox();
            this.radioECTC026 = new System.Windows.Forms.RadioButton();
            this.radioECB = new System.Windows.Forms.RadioButton();
            this.radioECA = new System.Windows.Forms.RadioButton();
            this.groupBoxEC.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBoxEC
            // 
            this.groupBoxEC.Controls.Add(this.radioECTC026);
            this.groupBoxEC.Controls.Add(this.radioECB);
            this.groupBoxEC.Controls.Add(this.radioECA);
            resources.ApplyResources(this.groupBoxEC, "groupBoxEC");
            this.groupBoxEC.Name = "groupBoxEC";
            this.groupBoxEC.TabStop = false;
            // 
            // radioECTC026
            // 
            resources.ApplyResources(this.radioECTC026, "radioECTC026");
            this.radioECTC026.Name = "radioECTC026";
            this.radioECTC026.TabStop = true;
            this.radioECTC026.UseVisualStyleBackColor = true;
            // 
            // radioECB
            // 
            resources.ApplyResources(this.radioECB, "radioECB");
            this.radioECB.Name = "radioECB";
            this.radioECB.UseVisualStyleBackColor = true;
            // 
            // radioECA
            // 
            resources.ApplyResources(this.radioECA, "radioECA");
            this.radioECA.Checked = true;
            this.radioECA.Name = "radioECA";
            this.radioECA.TabStop = true;
            this.radioECA.UseVisualStyleBackColor = true;
            // 
            // KeyControl2012_256X
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.groupBoxEC);
            this.Name = "KeyControl2012_256X";
            this.groupBoxEC.ResumeLayout(false);
            this.groupBoxEC.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBoxEC;
        private System.Windows.Forms.RadioButton radioECB;
        private System.Windows.Forms.RadioButton radioECA;
        private System.Windows.Forms.RadioButton radioECTC026;
    }
}
