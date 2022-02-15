namespace Aladdin.CAPI.GOST.GUI
{
    partial class KeyControl2001S
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(KeyControl2001S));
            this.groupBoxEC = new System.Windows.Forms.GroupBox();
            this.radioECC = new System.Windows.Forms.RadioButton();
            this.radioECB = new System.Windows.Forms.RadioButton();
            this.radioECA = new System.Windows.Forms.RadioButton();
            this.groupBoxHash = new System.Windows.Forms.GroupBox();
            this.radioHashCP = new System.Windows.Forms.RadioButton();
            this.radioHashT = new System.Windows.Forms.RadioButton();
            this.groupBoxEncryption = new System.Windows.Forms.GroupBox();
            this.radioD = new System.Windows.Forms.RadioButton();
            this.radioC = new System.Windows.Forms.RadioButton();
            this.radioB = new System.Windows.Forms.RadioButton();
            this.radioA = new System.Windows.Forms.RadioButton();
            this.groupBoxEC.SuspendLayout();
            this.groupBoxHash.SuspendLayout();
            this.groupBoxEncryption.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBoxEC
            // 
            this.groupBoxEC.Controls.Add(this.radioECC);
            this.groupBoxEC.Controls.Add(this.radioECB);
            this.groupBoxEC.Controls.Add(this.radioECA);
            resources.ApplyResources(this.groupBoxEC, "groupBoxEC");
            this.groupBoxEC.Name = "groupBoxEC";
            this.groupBoxEC.TabStop = false;
            // 
            // radioECC
            // 
            resources.ApplyResources(this.radioECC, "radioECC");
            this.radioECC.Name = "radioECC";
            this.radioECC.UseVisualStyleBackColor = true;
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
            // groupBoxHash
            // 
            this.groupBoxHash.Controls.Add(this.radioHashCP);
            this.groupBoxHash.Controls.Add(this.radioHashT);
            resources.ApplyResources(this.groupBoxHash, "groupBoxHash");
            this.groupBoxHash.Name = "groupBoxHash";
            this.groupBoxHash.TabStop = false;
            // 
            // radioHashCP
            // 
            resources.ApplyResources(this.radioHashCP, "radioHashCP");
            this.radioHashCP.Checked = true;
            this.radioHashCP.Name = "radioHashCP";
            this.radioHashCP.TabStop = true;
            this.radioHashCP.UseVisualStyleBackColor = true;
            // 
            // radioHashT
            // 
            resources.ApplyResources(this.radioHashT, "radioHashT");
            this.radioHashT.Name = "radioHashT";
            this.radioHashT.UseVisualStyleBackColor = true;
            // 
            // groupBoxEncryption
            // 
            this.groupBoxEncryption.Controls.Add(this.radioD);
            this.groupBoxEncryption.Controls.Add(this.radioC);
            this.groupBoxEncryption.Controls.Add(this.radioB);
            this.groupBoxEncryption.Controls.Add(this.radioA);
            resources.ApplyResources(this.groupBoxEncryption, "groupBoxEncryption");
            this.groupBoxEncryption.Name = "groupBoxEncryption";
            this.groupBoxEncryption.TabStop = false;
            // 
            // radioD
            // 
            resources.ApplyResources(this.radioD, "radioD");
            this.radioD.Name = "radioD";
            this.radioD.UseVisualStyleBackColor = true;
            // 
            // radioC
            // 
            resources.ApplyResources(this.radioC, "radioC");
            this.radioC.Name = "radioC";
            this.radioC.UseVisualStyleBackColor = true;
            // 
            // radioB
            // 
            resources.ApplyResources(this.radioB, "radioB");
            this.radioB.Name = "radioB";
            this.radioB.UseVisualStyleBackColor = true;
            // 
            // radioA
            // 
            resources.ApplyResources(this.radioA, "radioA");
            this.radioA.Checked = true;
            this.radioA.Name = "radioA";
            this.radioA.TabStop = true;
            this.radioA.UseVisualStyleBackColor = true;
            // 
            // KeyControl2001S
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.groupBoxEncryption);
            this.Controls.Add(this.groupBoxHash);
            this.Controls.Add(this.groupBoxEC);
            this.Name = "KeyControl2001S";
            this.groupBoxEC.ResumeLayout(false);
            this.groupBoxEC.PerformLayout();
            this.groupBoxHash.ResumeLayout(false);
            this.groupBoxHash.PerformLayout();
            this.groupBoxEncryption.ResumeLayout(false);
            this.groupBoxEncryption.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBoxEC;
        private System.Windows.Forms.RadioButton radioECC;
        private System.Windows.Forms.RadioButton radioECB;
        private System.Windows.Forms.RadioButton radioECA;
        private System.Windows.Forms.GroupBox groupBoxHash;
        private System.Windows.Forms.RadioButton radioHashCP;
        private System.Windows.Forms.RadioButton radioHashT;
        private System.Windows.Forms.GroupBox groupBoxEncryption;
        private System.Windows.Forms.RadioButton radioD;
        private System.Windows.Forms.RadioButton radioC;
        private System.Windows.Forms.RadioButton radioB;
        private System.Windows.Forms.RadioButton radioA;
    }
}
