namespace Aladdin.CAPI.GUI
{
    partial class BioEnrollDialog
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(BioEnrollDialog));
            this.groupRight = new System.Windows.Forms.GroupBox();
            this.checkRightThumb = new System.Windows.Forms.CheckBox();
            this.checkRightMiddle = new System.Windows.Forms.CheckBox();
            this.checkRightIndex = new System.Windows.Forms.CheckBox();
            this.checkRightLittle = new System.Windows.Forms.CheckBox();
            this.checkRightRing = new System.Windows.Forms.CheckBox();
            this.groupLeft = new System.Windows.Forms.GroupBox();
            this.checkLeftIndex = new System.Windows.Forms.CheckBox();
            this.checkLeftThumb = new System.Windows.Forms.CheckBox();
            this.checkLeftMiddle = new System.Windows.Forms.CheckBox();
            this.checkLeftRing = new System.Windows.Forms.CheckBox();
            this.checkLeftLittle = new System.Windows.Forms.CheckBox();
            this.buttonCancel = new System.Windows.Forms.Button();
            this.comboReader = new System.Windows.Forms.ComboBox();
            this.imageFinger = new System.Windows.Forms.PictureBox();
            this.groupFar = new System.Windows.Forms.GroupBox();
            this.far100 = new System.Windows.Forms.RadioButton();
            this.far1000 = new System.Windows.Forms.RadioButton();
            this.far10000 = new System.Windows.Forms.RadioButton();
            this.far100000 = new System.Windows.Forms.RadioButton();
            this.far1000000 = new System.Windows.Forms.RadioButton();
            this.buttonOK = new System.Windows.Forms.Button();
            this.labelReader = new System.Windows.Forms.Label();
            this.groupSelect = new System.Windows.Forms.GroupBox();
            this.labelFinger = new System.Windows.Forms.Label();
            this.comboFinger = new System.Windows.Forms.ComboBox();
            this.textInfo = new System.Windows.Forms.TextBox();
            this.groupScan = new System.Windows.Forms.GroupBox();
            this.labelQualityValue = new System.Windows.Forms.Label();
            this.labelQuality = new System.Windows.Forms.Label();
            this.trackBarQuality = new System.Windows.Forms.TrackBar();
            this.buttonStop = new System.Windows.Forms.Button();
            this.buttonStart = new System.Windows.Forms.Button();
            this.comboBoxUser = new System.Windows.Forms.ComboBox();
            this.labelType = new System.Windows.Forms.Label();
            this.groupRight.SuspendLayout();
            this.groupLeft.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.imageFinger)).BeginInit();
            this.groupFar.SuspendLayout();
            this.groupSelect.SuspendLayout();
            this.groupScan.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.trackBarQuality)).BeginInit();
            this.SuspendLayout();
            // 
            // groupRight
            // 
            resources.ApplyResources(this.groupRight, "groupRight");
            this.groupRight.Controls.Add(this.checkRightThumb);
            this.groupRight.Controls.Add(this.checkRightMiddle);
            this.groupRight.Controls.Add(this.checkRightIndex);
            this.groupRight.Controls.Add(this.checkRightLittle);
            this.groupRight.Controls.Add(this.checkRightRing);
            this.groupRight.Name = "groupRight";
            this.groupRight.TabStop = false;
            // 
            // checkRightThumb
            // 
            resources.ApplyResources(this.checkRightThumb, "checkRightThumb");
            this.checkRightThumb.Name = "checkRightThumb";
            this.checkRightThumb.UseVisualStyleBackColor = true;
            this.checkRightThumb.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkRightMiddle
            // 
            resources.ApplyResources(this.checkRightMiddle, "checkRightMiddle");
            this.checkRightMiddle.Name = "checkRightMiddle";
            this.checkRightMiddle.UseVisualStyleBackColor = true;
            this.checkRightMiddle.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkRightIndex
            // 
            resources.ApplyResources(this.checkRightIndex, "checkRightIndex");
            this.checkRightIndex.Name = "checkRightIndex";
            this.checkRightIndex.UseVisualStyleBackColor = true;
            this.checkRightIndex.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkRightLittle
            // 
            resources.ApplyResources(this.checkRightLittle, "checkRightLittle");
            this.checkRightLittle.Name = "checkRightLittle";
            this.checkRightLittle.UseVisualStyleBackColor = true;
            this.checkRightLittle.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkRightRing
            // 
            resources.ApplyResources(this.checkRightRing, "checkRightRing");
            this.checkRightRing.Name = "checkRightRing";
            this.checkRightRing.UseVisualStyleBackColor = true;
            this.checkRightRing.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // groupLeft
            // 
            resources.ApplyResources(this.groupLeft, "groupLeft");
            this.groupLeft.Controls.Add(this.checkLeftIndex);
            this.groupLeft.Controls.Add(this.checkLeftThumb);
            this.groupLeft.Controls.Add(this.checkLeftMiddle);
            this.groupLeft.Controls.Add(this.checkLeftRing);
            this.groupLeft.Controls.Add(this.checkLeftLittle);
            this.groupLeft.Name = "groupLeft";
            this.groupLeft.TabStop = false;
            // 
            // checkLeftIndex
            // 
            resources.ApplyResources(this.checkLeftIndex, "checkLeftIndex");
            this.checkLeftIndex.Name = "checkLeftIndex";
            this.checkLeftIndex.UseVisualStyleBackColor = true;
            this.checkLeftIndex.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkLeftThumb
            // 
            resources.ApplyResources(this.checkLeftThumb, "checkLeftThumb");
            this.checkLeftThumb.Name = "checkLeftThumb";
            this.checkLeftThumb.UseVisualStyleBackColor = true;
            this.checkLeftThumb.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkLeftMiddle
            // 
            resources.ApplyResources(this.checkLeftMiddle, "checkLeftMiddle");
            this.checkLeftMiddle.Name = "checkLeftMiddle";
            this.checkLeftMiddle.UseVisualStyleBackColor = true;
            this.checkLeftMiddle.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkLeftRing
            // 
            resources.ApplyResources(this.checkLeftRing, "checkLeftRing");
            this.checkLeftRing.Name = "checkLeftRing";
            this.checkLeftRing.UseVisualStyleBackColor = true;
            this.checkLeftRing.Click += new System.EventHandler(this.OnCheckClick);
            // 
            // checkLeftLittle
            // 
            resources.ApplyResources(this.checkLeftLittle, "checkLeftLittle");
            this.checkLeftLittle.Name = "checkLeftLittle";
            this.checkLeftLittle.UseVisualStyleBackColor = true;
            this.checkLeftLittle.Click += new System.EventHandler(this.OnCheckClick);
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
            // groupFar
            // 
            resources.ApplyResources(this.groupFar, "groupFar");
            this.groupFar.Controls.Add(this.far100);
            this.groupFar.Controls.Add(this.far1000);
            this.groupFar.Controls.Add(this.far10000);
            this.groupFar.Controls.Add(this.far100000);
            this.groupFar.Controls.Add(this.far1000000);
            this.groupFar.Name = "groupFar";
            this.groupFar.TabStop = false;
            // 
            // far100
            // 
            resources.ApplyResources(this.far100, "far100");
            this.far100.Name = "far100";
            this.far100.TabStop = true;
            this.far100.UseVisualStyleBackColor = true;
            // 
            // far1000
            // 
            resources.ApplyResources(this.far1000, "far1000");
            this.far1000.Name = "far1000";
            this.far1000.TabStop = true;
            this.far1000.UseVisualStyleBackColor = true;
            // 
            // far10000
            // 
            resources.ApplyResources(this.far10000, "far10000");
            this.far10000.Name = "far10000";
            this.far10000.TabStop = true;
            this.far10000.UseVisualStyleBackColor = true;
            // 
            // far100000
            // 
            resources.ApplyResources(this.far100000, "far100000");
            this.far100000.Name = "far100000";
            this.far100000.TabStop = true;
            this.far100000.UseVisualStyleBackColor = true;
            // 
            // far1000000
            // 
            resources.ApplyResources(this.far1000000, "far1000000");
            this.far1000000.Name = "far1000000";
            this.far1000000.TabStop = true;
            this.far1000000.UseVisualStyleBackColor = true;
            // 
            // buttonOK
            // 
            resources.ApplyResources(this.buttonOK, "buttonOK");
            this.buttonOK.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.buttonOK.Name = "buttonOK";
            this.buttonOK.UseVisualStyleBackColor = true;
            // 
            // labelReader
            // 
            resources.ApplyResources(this.labelReader, "labelReader");
            this.labelReader.Name = "labelReader";
            // 
            // groupSelect
            // 
            resources.ApplyResources(this.groupSelect, "groupSelect");
            this.groupSelect.Controls.Add(this.groupRight);
            this.groupSelect.Controls.Add(this.groupLeft);
            this.groupSelect.Name = "groupSelect";
            this.groupSelect.TabStop = false;
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
            // groupScan
            // 
            resources.ApplyResources(this.groupScan, "groupScan");
            this.groupScan.Controls.Add(this.labelQualityValue);
            this.groupScan.Controls.Add(this.labelQuality);
            this.groupScan.Controls.Add(this.trackBarQuality);
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
            // BioEnrollDialog
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.comboBoxUser);
            this.Controls.Add(this.groupScan);
            this.Controls.Add(this.groupFar);
            this.Controls.Add(this.labelType);
            this.Controls.Add(this.groupSelect);
            this.Controls.Add(this.buttonOK);
            this.Controls.Add(this.buttonCancel);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "BioEnrollDialog";
            this.Load += new System.EventHandler(this.OnLoad);
            this.groupRight.ResumeLayout(false);
            this.groupRight.PerformLayout();
            this.groupLeft.ResumeLayout(false);
            this.groupLeft.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.imageFinger)).EndInit();
            this.groupFar.ResumeLayout(false);
            this.groupFar.PerformLayout();
            this.groupSelect.ResumeLayout(false);
            this.groupScan.ResumeLayout(false);
            this.groupScan.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.trackBarQuality)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

		private System.Windows.Forms.GroupBox groupRight;
		private System.Windows.Forms.GroupBox groupLeft;
        private System.Windows.Forms.Button buttonCancel;
        private System.Windows.Forms.ComboBox comboReader;
        private System.Windows.Forms.PictureBox imageFinger;
        private System.Windows.Forms.GroupBox groupFar;
        private System.Windows.Forms.RadioButton far100;
        private System.Windows.Forms.RadioButton far1000;
        private System.Windows.Forms.RadioButton far10000;
        private System.Windows.Forms.RadioButton far100000;
		private System.Windows.Forms.RadioButton far1000000;
		private System.Windows.Forms.Button buttonOK;
		private System.Windows.Forms.CheckBox checkRightThumb;
		private System.Windows.Forms.CheckBox checkRightMiddle;
		private System.Windows.Forms.CheckBox checkRightIndex;
		private System.Windows.Forms.CheckBox checkRightLittle;
		private System.Windows.Forms.CheckBox checkRightRing;
		private System.Windows.Forms.CheckBox checkLeftThumb;
		private System.Windows.Forms.CheckBox checkLeftMiddle;
		private System.Windows.Forms.CheckBox checkLeftRing;
		private System.Windows.Forms.CheckBox checkLeftLittle;
		private System.Windows.Forms.Label labelReader;
		private System.Windows.Forms.GroupBox groupSelect;
		private System.Windows.Forms.Label labelFinger;
		private System.Windows.Forms.ComboBox comboFinger;
		private System.Windows.Forms.TextBox textInfo;
		private System.Windows.Forms.CheckBox checkLeftIndex;
		private System.Windows.Forms.GroupBox groupScan;
		private System.Windows.Forms.Button buttonStop;
        private System.Windows.Forms.Button buttonStart;
        private System.Windows.Forms.ComboBox comboBoxUser;
        private System.Windows.Forms.Label labelType;
        private System.Windows.Forms.Label labelQualityValue;
        private System.Windows.Forms.Label labelQuality;
        private System.Windows.Forms.TrackBar trackBarQuality;
    }
}