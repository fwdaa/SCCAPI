namespace Aladdin.CAPI.GUI
{
    partial class BioPinMatchDialog
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
            if (disposing) { captureControl.Dispose();
            
                if (components != null) components.Dispose(); 
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(BioPinMatchDialog));
            this.buttonCancel = new System.Windows.Forms.Button();
            this.comboReader = new System.Windows.Forms.ComboBox();
            this.imageFinger = new System.Windows.Forms.PictureBox();
            this.buttonOK = new System.Windows.Forms.Button();
            this.labelReader = new System.Windows.Forms.Label();
            this.labelFinger = new System.Windows.Forms.Label();
            this.comboFinger = new System.Windows.Forms.ComboBox();
            this.textInfo = new System.Windows.Forms.TextBox();
            this.buttonStop = new System.Windows.Forms.Button();
            this.buttonStart = new System.Windows.Forms.Button();
            this.groupScan = new System.Windows.Forms.GroupBox();
            this.labelQualityValue = new System.Windows.Forms.Label();
            this.labelQuality = new System.Windows.Forms.Label();
            this.trackBarQuality = new System.Windows.Forms.TrackBar();
            this.labelState = new System.Windows.Forms.Label();
            this.labelPIN = new System.Windows.Forms.Label();
            this.textBoxPIN = new System.Windows.Forms.TextBox();
            this.textBoxLang = new System.Windows.Forms.TextBox();
            this.labelProvider = new System.Windows.Forms.Label();
            this.textBoxProvider = new System.Windows.Forms.TextBox();
            this.labelObject = new System.Windows.Forms.Label();
            this.textBoxObject = new System.Windows.Forms.TextBox();
            this.comboBoxUser = new System.Windows.Forms.ComboBox();
            this.labelType = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.imageFinger)).BeginInit();
            this.groupScan.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.trackBarQuality)).BeginInit();
            this.SuspendLayout();
            // 
            // buttonCancel
            // 
            resources.ApplyResources(this.buttonCancel, "buttonCancel");
            this.buttonCancel.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.buttonCancel.Name = "buttonCancel";
            this.buttonCancel.UseVisualStyleBackColor = true;
            // 
            // comboReader
            // 
            resources.ApplyResources(this.comboReader, "comboReader");
            this.comboReader.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboReader.FormattingEnabled = true;
            this.comboReader.Name = "comboReader";
            // 
            // imageFinger
            // 
            resources.ApplyResources(this.imageFinger, "imageFinger");
            this.imageFinger.Name = "imageFinger";
            this.imageFinger.TabStop = false;
            // 
            // buttonOK
            // 
            resources.ApplyResources(this.buttonOK, "buttonOK");
            this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.UseVisualStyleBackColor = true;
            this.buttonOK.Click += new System.EventHandler(this.OnButtonOK);
            // 
            // labelReader
            // 
            resources.ApplyResources(this.labelReader, "labelReader");
            this.labelReader.Name = "labelReader";
            // 
            // labelFinger
            // 
            resources.ApplyResources(this.labelFinger, "labelFinger");
            this.labelFinger.Name = "labelFinger";
            // 
            // comboFinger
            // 
            resources.ApplyResources(this.comboFinger, "comboFinger");
            this.comboFinger.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboFinger.FormattingEnabled = true;
            this.comboFinger.Items.AddRange(new object[] {
            resources.GetString("comboFinger.Items"),
            resources.GetString("comboFinger.Items1"),
            resources.GetString("comboFinger.Items2"),
            resources.GetString("comboFinger.Items3"),
            resources.GetString("comboFinger.Items4"),
            resources.GetString("comboFinger.Items5"),
            resources.GetString("comboFinger.Items6"),
            resources.GetString("comboFinger.Items7"),
            resources.GetString("comboFinger.Items8"),
            resources.GetString("comboFinger.Items9")});
            this.comboFinger.Name = "comboFinger";
            // 
            // textInfo
            // 
            resources.ApplyResources(this.textInfo, "textInfo");
            this.textInfo.Name = "textInfo";
            this.textInfo.ReadOnly = true;
            // 
            // buttonStop
            // 
            resources.ApplyResources(this.buttonStop, "buttonStop");
            this.buttonStop.Name = "buttonStop";
            this.buttonStop.UseVisualStyleBackColor = true;
            this.buttonStop.Click += new System.EventHandler(this.OnStop);
            // 
            // buttonStart
            // 
            resources.ApplyResources(this.buttonStart, "buttonStart");
            this.buttonStart.Name = "buttonStart";
            this.buttonStart.UseVisualStyleBackColor = true;
            this.buttonStart.Click += new System.EventHandler(this.OnStart);
            // 
            // groupScan
            // 
            resources.ApplyResources(this.groupScan, "groupScan");
            this.groupScan.Controls.Add(this.labelQualityValue);
            this.groupScan.Controls.Add(this.labelQuality);
            this.groupScan.Controls.Add(this.trackBarQuality);
            this.groupScan.Controls.Add(this.labelState);
            this.groupScan.Controls.Add(this.buttonStop);
            this.groupScan.Controls.Add(this.buttonStart);
            this.groupScan.Controls.Add(this.textInfo);
            this.groupScan.Controls.Add(this.comboFinger);
            this.groupScan.Controls.Add(this.labelFinger);
            this.groupScan.Controls.Add(this.imageFinger);
            this.groupScan.Controls.Add(this.labelReader);
            this.groupScan.Controls.Add(this.comboReader);
            this.groupScan.Name = "groupScan";
            this.groupScan.TabStop = false;
            // 
            // labelQualityValue
            // 
            resources.ApplyResources(this.labelQualityValue, "labelQualityValue");
            this.labelQualityValue.Name = "labelQualityValue";
            // 
            // labelQuality
            // 
            resources.ApplyResources(this.labelQuality, "labelQuality");
            this.labelQuality.Name = "labelQuality";
            // 
            // trackBarQuality
            // 
            resources.ApplyResources(this.trackBarQuality, "trackBarQuality");
            this.trackBarQuality.LargeChange = 20;
            this.trackBarQuality.Maximum = 100;
            this.trackBarQuality.Name = "trackBarQuality";
            this.trackBarQuality.SmallChange = 10;
            this.trackBarQuality.Value = 50;
            this.trackBarQuality.Scroll += new System.EventHandler(this.OnQualityScroll);
            // 
            // labelState
            // 
            resources.ApplyResources(this.labelState, "labelState");
            this.labelState.Name = "labelState";
            // 
            // labelPIN
            // 
            resources.ApplyResources(this.labelPIN, "labelPIN");
            this.labelPIN.Name = "labelPIN";
            // 
            // textBoxPIN
            // 
            resources.ApplyResources(this.textBoxPIN, "textBoxPIN");
            this.textBoxPIN.Name = "textBoxPIN";
            this.textBoxPIN.TextChanged += new System.EventHandler(this.OnPasswordChanged);
            // 
            // textBoxLang
            // 
            resources.ApplyResources(this.textBoxLang, "textBoxLang");
            this.textBoxLang.Name = "textBoxLang";
            this.textBoxLang.ReadOnly = true;
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
            // labelObject
            // 
            resources.ApplyResources(this.labelObject, "labelObject");
            this.labelObject.Name = "labelObject";
            // 
            // textBoxObject
            // 
            resources.ApplyResources(this.textBoxObject, "textBoxObject");
            this.textBoxObject.Name = "textBoxObject";
            this.textBoxObject.ReadOnly = true;
            // 
            // comboBoxUser
            // 
            resources.ApplyResources(this.comboBoxUser, "comboBoxUser");
            this.comboBoxUser.FormattingEnabled = true;
            this.comboBoxUser.Items.AddRange(new object[] {
            resources.GetString("comboBoxUser.Items"),
            resources.GetString("comboBoxUser.Items1")});
            this.comboBoxUser.Name = "comboBoxUser";
            this.comboBoxUser.SelectedIndexChanged += new System.EventHandler(this.OnUserChanged);
            // 
            // labelType
            // 
            resources.ApplyResources(this.labelType, "labelType");
            this.labelType.Name = "labelType";
            // 
            // BioPinMatchDialog
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.comboBoxUser);
            this.Controls.Add(this.labelType);
            this.Controls.Add(this.labelProvider);
            this.Controls.Add(this.textBoxProvider);
            this.Controls.Add(this.labelObject);
            this.Controls.Add(this.textBoxObject);
            this.Controls.Add(this.textBoxLang);
            this.Controls.Add(this.textBoxPIN);
            this.Controls.Add(this.labelPIN);
            this.Controls.Add(this.groupScan);
            this.Controls.Add(this.buttonOK);
            this.Controls.Add(this.buttonCancel);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "BioPinMatchDialog";
            this.Load += new System.EventHandler(this.OnLoad);
            ((System.ComponentModel.ISupportInitialize)(this.imageFinger)).EndInit();
            this.groupScan.ResumeLayout(false);
            this.groupScan.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.trackBarQuality)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button buttonCancel;
        private System.Windows.Forms.ComboBox comboReader;
        private System.Windows.Forms.PictureBox imageFinger;
        private System.Windows.Forms.Button buttonOK;
        private System.Windows.Forms.Label labelReader;
		private System.Windows.Forms.Label labelFinger;
		private System.Windows.Forms.ComboBox comboFinger;
        private System.Windows.Forms.TextBox textInfo;
		private System.Windows.Forms.Button buttonStop;
		private System.Windows.Forms.Button buttonStart;
        private System.Windows.Forms.GroupBox groupScan;
        private System.Windows.Forms.Label labelState;
		private System.Windows.Forms.Label labelPIN;
		private System.Windows.Forms.TextBox textBoxPIN;
		private System.Windows.Forms.TextBox textBoxLang;
		private System.Windows.Forms.Label labelProvider;
		private System.Windows.Forms.TextBox textBoxProvider;
		private System.Windows.Forms.Label labelObject;
		private System.Windows.Forms.TextBox textBoxObject;
        private System.Windows.Forms.ComboBox comboBoxUser;
        private System.Windows.Forms.Label labelType;
        private System.Windows.Forms.Label labelQuality;
        private System.Windows.Forms.TrackBar trackBarQuality;
        private System.Windows.Forms.Label labelQualityValue;
    }
}