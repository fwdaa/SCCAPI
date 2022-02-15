namespace Example4
{
    partial class Form1
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
            this.bmpPicture = new System.Windows.Forms.PictureBox();
            this.wsqPicture = new System.Windows.Forms.PictureBox();
            this.button1 = new System.Windows.Forms.Button();
            this.button2 = new System.Windows.Forms.Button();
            this.button3 = new System.Windows.Forms.Button();
            this.button4 = new System.Windows.Forms.Button();
            this.openWSQFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.openBMPFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.saveToBmpDialog1 = new System.Windows.Forms.SaveFileDialog();
            this.saveToWsqFileDialog1 = new System.Windows.Forms.SaveFileDialog();
            ((System.ComponentModel.ISupportInitialize)(this.bmpPicture)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.wsqPicture)).BeginInit();
            this.SuspendLayout();
            // 
            // bmpPicture
            // 
            this.bmpPicture.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.bmpPicture.Location = new System.Drawing.Point(12, 12);
            this.bmpPicture.Name = "bmpPicture";
            this.bmpPicture.Size = new System.Drawing.Size(298, 298);
            this.bmpPicture.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.bmpPicture.TabIndex = 0;
            this.bmpPicture.TabStop = false;
            // 
            // wsqPicture
            // 
            this.wsqPicture.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.wsqPicture.Location = new System.Drawing.Point(316, 12);
            this.wsqPicture.Name = "wsqPicture";
            this.wsqPicture.Size = new System.Drawing.Size(298, 298);
            this.wsqPicture.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.wsqPicture.TabIndex = 1;
            this.wsqPicture.TabStop = false;
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(316, 316);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(298, 23);
            this.button1.TabIndex = 2;
            this.button1.Text = "WSQ file to toolkit image";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // button2
            // 
            this.button2.Location = new System.Drawing.Point(12, 316);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(298, 23);
            this.button2.TabIndex = 3;
            this.button2.Text = "BMP file to toolkit image";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // button3
            // 
            this.button3.Location = new System.Drawing.Point(316, 345);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(298, 23);
            this.button3.TabIndex = 4;
            this.button3.Text = "Toolkit image to WSQ file";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new System.EventHandler(this.button3_Click);
            // 
            // button4
            // 
            this.button4.Location = new System.Drawing.Point(12, 345);
            this.button4.Name = "button4";
            this.button4.Size = new System.Drawing.Size(298, 23);
            this.button4.TabIndex = 5;
            this.button4.Text = "Toolkit image to BMP file";
            this.button4.UseVisualStyleBackColor = true;
            this.button4.Click += new System.EventHandler(this.button4_Click);
            // 
            // openWSQFileDialog1
            // 
            this.openWSQFileDialog1.Filter = "Fingerprint Image (*.wsq)|*.wsq";
            // 
            // openBMPFileDialog1
            // 
            this.openBMPFileDialog1.Filter = "Fingerprint Image (*.bmp)|*.bmp";
            // 
            // saveToBmpDialog1
            // 
            this.saveToBmpDialog1.Filter = "Bitmap Image (*.bmp)|*.bmp";
            // 
            // saveToWsqFileDialog1
            // 
            this.saveToWsqFileDialog1.Filter = "WSQ Image (*.wsq)|*.wsq";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(627, 380);
            this.Controls.Add(this.button4);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.wsqPicture);
            this.Controls.Add(this.bmpPicture);
            this.Name = "Form1";
            this.Text = "BMP and WSQ image handling";
            ((System.ComponentModel.ISupportInitialize)(this.bmpPicture)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.wsqPicture)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.PictureBox bmpPicture;
        private System.Windows.Forms.PictureBox wsqPicture;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.Button button4;
        private System.Windows.Forms.OpenFileDialog openWSQFileDialog1;
        private System.Windows.Forms.OpenFileDialog openBMPFileDialog1;
        private System.Windows.Forms.SaveFileDialog saveToBmpDialog1;
        private System.Windows.Forms.SaveFileDialog saveToWsqFileDialog1;
    }
}

