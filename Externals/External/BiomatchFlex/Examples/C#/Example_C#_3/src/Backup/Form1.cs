using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using PreciseBiometrics.BMFH;
using System.Threading;

namespace Example3
{
    public partial class Form1 : Form
    {
        public BioMatch         toolkit = new BioMatch();
        private BM_FarLevel     far_level = BM_FarLevel.Far10000;
        private BMFH_Template   MoCtemplate = null;
        Thread                  enrolmentThread;
        internal bool           fingerDone = false;
        internal BM_Reader      selectedReader = null;
        internal BM_Finger      selectedFinger;
        internal bool           liftFinger = false;
        internal string         qtext = "Quality Check";
        internal string         qres = "Resampling";
        internal string         placefinger = "Place Finger";
        internal string         liftfinger = "Lift Finger";
        internal string         currentFeedback = "";
        internal Font           FeedBackFont = 
            new Font("Microsoft Sans Serif", 18, FontStyle.Regular);
        internal Color          FeedbackBackgroundColor = Color.Orange;
        internal Color          FeedBackTextColor = Color.Black;
        internal int            FeedBackTransparency = 155;
        internal StringFormat   stringFormat = new StringFormat();
        internal Bitmap         Img; 
        internal Bitmap         Img2;

        
        delegate void Invoker(string parameter);
        delegate void ButtonInvoker(bool parameter);
        delegate void StatusInvoker(int phase);
        delegate void ImageInvoker(BM_Image image);
        delegate void ImageInvoker2();
        
        public Form1()
        {
            InitializeComponent();
            Img = new Bitmap(Example3.Properties.Resources.left_han);
            Img2 = new Bitmap(Example3.Properties.Resources.right_ha); 
            Img.MakeTransparent(Img.GetPixel(10, 10));
            Img2.MakeTransparent(Img2.GetPixel(10, 10));
            handL.Image = Img;
            handR.Image = Img2;
            selectedReader = null;
            selectedFinger = BM_Finger.Unknown;
            stringFormat.Alignment = StringAlignment.Center;
            stringFormat.LineAlignment = StringAlignment.Center;
            enrolmentThread = new System.Threading.Thread(doEnrolment);
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            /* Register biometric callback */
            toolkit.BiometricCallback += 
                new BioMatch.BiometricEventHandler(BioEventHandler);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            int i;
            BM_Reader[] readers;

            comboBox1.Items.Clear();

            

            /* Retreive available readers */
            toolkit.ListBiometricReaders(out readers);

            if (readers != null)
            {
                for (i = 0; i < readers.Length; i++)
                {
                    comboBox1.Items.Add(readers[i]);
                }
                comboBox1.SelectedIndex = 0;
                
                selectedReader =
                (BM_Reader)comboBox1.Items[comboBox1.SelectedIndex];
            }
        }

        public void SafeButtonControl(bool enable)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new ButtonInvoker(SafeButtonControl), enable);
                return;
            }
            this.button2.Enabled = enable;
            this.button4.Enabled = enable;
        }

        /* Threadsafe update of image */
        private void SafeSetImage(BM_Image image)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new ImageInvoker(SafeSetImage), image);
                return;
            }
            fingerBox.Image = image.ToImage();
            fingerBox.Refresh();
        }

        private void SafeDisposeImage()
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new ImageInvoker2(SafeDisposeImage));
                return;
            }
            fingerBox.Image.Dispose();
        }

        private void BioEventHandler(int token, Object context)
        {
            BM_Image            dummy_image, image;
            BM_ImageCondition   dummy_condition;
            BM_ImagePresent     present;
            uint                imageSize = 0;
            int                 dummy_quality;
            
            toolkit.CB_FingerStatus(token,
                                    out dummy_image,
                                    out dummy_quality,
                                    out dummy_condition,
                                    out present,
                                    BM_StatusOption.Present);

            if (present == BM_ImagePresent.False)
            {
                setFeedback(placefinger);
            }
            else
            {
                if (liftFinger)
                {
                    setFeedback(liftfinger);
                }
                else
                {
                    clearOverlay();
                }
            }

            toolkit.CB_GetImageForViewing(
                token,
                (uint)fingerBox.Width,
                (uint)fingerBox.Height,
                (uint)((((fingerBox.Width - 1) / 4) + 1) * 4), 
                out image, 
                out imageSize);

            SafeSetImage(image);

            showFeedback();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            
            textBox1.Clear();
            button4.Enabled = false;
            button2.Enabled = false;

            /* Create and start enrollment thread */
            enrolmentThread = new Thread(doEnrolment);
            enrolmentThread.Start();
        }

        /* Update the symbols in the custom progess panel */
        public void SetStatus(int phase)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new StatusInvoker(SetStatus), phase);
                return;
            }
            switch (phase)
            {
                case 0:
                    step0.Text = "»";
                    break;
                case 1:
                    step0.Text = "√";
                    step1.Text = "»";
                    break;
                case 2:
                    step0.Text = "√";
                    step1.Text = "√";
                    step2.Text = "»";
                    step3.Text = "";
                    break;
                case 3:
                    labelA.Text = qres;
                    labelB.Text = qtext;
                    labelB.Visible = true;
                    step3.Visible = true;
                    step0.Text = "√";
                    step1.Text = "√";
                    step2.Text = "√";
                    step3.Text = "»";
                    break;
                case 11:
                    step0.Text = "√";
                    step1.Text = "√";
                    step2.Text = "√";
                    break;
                case 12:
                    step0.Text = "√";
                    step1.Text = "√";
                    step2.Text = "√";
                    step3.Text = "√";
                    break;
                case 9:
                    labelB.Visible = false;
                    step3.Visible = false;
                    labelA.Text = qtext;
                    step0.Text = "";
                    step1.Text = "";
                    step2.Text = "";
                    step3.Text = "";
                    break;
                case 99:
                    step0.Text = "X";
                    step1.Text = "X";
                    step2.Text = "X";
                    step3.Visible = false;
                    labelA.Text = qtext;
                    labelA.Visible = true;
                    labelB.Visible = false;
                    break;
                default:
                    break;
            }
            Update();
        }

        private void SafeSetText(String text)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Invoker(SafeSetText), text);
                return;
            }
            this.textBox1.Text = text;
        }

        private void SafeAppendText(String text)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new Invoker(SafeAppendText), text);
                return;
            }
            this.textBox1.AppendText(text);
        }

        private bool captureImage(out BM_Image image)
        {
            BM_ReturnCode   result = BM_ReturnCode.Ok;
            
            image = null;

            SafeSetText("Place/Swipe finger on sensor.");

            /* Capture image */
            result = toolkit.CaptureImage(selectedReader,
                                          BioMatch.TIMEOUT_FOREVER, 
                                          out image, 
                                          null);
            switch (result)
            {
                case BM_ReturnCode.Ok:
                    SafeAppendText(" OK");
                    return true;
                case BM_ReturnCode.Cancelled:   
                    SafeSetText("Cancelled");       
                    return false;
                case BM_ReturnCode.TimedOut:    
                    SafeSetText("Timed out");       
                    return false;
                default:                        
                    SafeSetText("Serious error!");  
                    return false;
            }
        }

        internal void doEnrolment()
        {
            BM_Image        image1;
            BMFH_Template   template;
            Int32           status = 1; /* Used to indicate states in 
                                         * the custom progress panel */
            bool            validated = false;
            BM_ReturnCode   result;

            if (selectedReader == null)
            {
                MessageBox.Show("No reader is currently selected.",
                                "Error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                SafeButtonControl(true);
                return;
            }

            if (selectedFinger == BM_Finger.Unknown)
            {
                MessageBox.Show("No finger is currently selected.",
                                "Error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                SafeButtonControl(true);
                return;
            }
            /* Reset the status indicators */
            SetStatus(9);

            SetStatus(0);

            /* Capture image */
            if (!captureImage(out image1))
            {
                SafeButtonControl(true);
                return;
            }
            clearOverlay();

            /* Create template */
            result = toolkit.CreateEnrolTemplateFromImage(image1, 
                                                          far_level, 
                                                          out template);
            if (result != BM_ReturnCode.Ok)
            {
                SafeSetText("Template creation failed!");
                SafeButtonControl(true);
                return;
            }

            do
            {
                /* 1. Lift finger */
                liftFinger = true;
                result = toolkit.WaitForNoFinger(selectedReader, 
                                                 BioMatch.TIMEOUT_FOREVER, 
                                                 "Waiting for no Finger");
                liftFinger = false;
                if (result != BM_ReturnCode.Ok)
                {
                    SafeSetText("WaitForNoFinger failed!");
                    SafeButtonControl(true);
                    return;
                }
                SetStatus(status);

                /* 2. Capture a new image */
                if (!captureImage(out image1))
                {
                    SafeButtonControl(true);
                    return;
                }
                SetStatus(status + 1);
                clearOverlay();

                /* 3. Validate template */
                result = toolkit.ValidateEnrolmentTemplateWithImage(
                    image1, template, out validated);
                if (result != BM_ReturnCode.Ok)
                {
                    SafeSetText("Template validation failed!");
                    SafeButtonControl(true);
                    return;
                }

                /* 4. Check quality */
                if (!validated)
                {
                    /* Template NOT validated - create new template from last captured image. */
                    /* 5. Create MoC template for enrollment */
                    result = toolkit.CreateEnrolTemplateFromImage(image1, 
                        far_level, out template);
                    if (result != BM_ReturnCode.Ok)
                    {
                        SafeSetText("Template creation failed!");
                        SafeButtonControl(true);
                        return;
                    }

                    SetStatus(status + 2);
                    status = 2;
                    Thread.Sleep(300);
                }
                else
                {
                    SetStatus(status + 10);

                    /* Template validated - create template for enrollment from last captured image. */
                    /* 5. Create MoC template */

                    /* Set finger in image */
                    image1.Finger = selectedFinger;

                    result = toolkit.CreateEnrolTemplateFromImage(image1, 
                        far_level, out MoCtemplate);
                    if (result != BM_ReturnCode.Ok)
                    {
                        SafeSetText("Template creation failed!");
                        SafeButtonControl(true);
                        return;
                    }
                }
            }
            while (!validated);

            SafeSetText("Finger Enrolled");
            SafeButtonControl(true);
        }

        private void radioButton11_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton11.Checked)
            {
                far_level = BM_FarLevel.Far100;
            }
        }

        private void radioButton12_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton12.Checked)
            {
                far_level = BM_FarLevel.Far1000;
            }
        }

        private void radioButton13_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton13.Checked)
            {
                far_level = BM_FarLevel.Far10000;
            }
        }

        private void radioButton14_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton14.Checked)
            {
                far_level = BM_FarLevel.Far100000;
            }
        }

        private void radioButton15_CheckedChanged(object sender, EventArgs e)
        {
            if (radioButton15.Checked)
            {
                far_level = BM_FarLevel.Far1000000;
            }
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            selectedReader = (BM_Reader)comboBox1.Items[comboBox1.SelectedIndex];
        }

        private void radioButton10_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.LeftLittle;
        }

        private void radioButton9_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.LeftRing;
        }

        private void radioButton8_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.LeftMiddle;
        }

        private void radioButton7_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.LeftIndex;
        }

        private void radioButton6_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.LeftThumb;
        }

        private void radioButton5_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.RightThumb;
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.RightIndex;
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.RightMiddle;
        }

        private void radioButton3_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.RightRing;
        }

        private void radioButton4_CheckedChanged(object sender, EventArgs e)
        {
            selectedFinger = BM_Finger.RightLittle;
        }

        internal void clearOverlay()
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new ImageInvoker2(clearOverlay));
                return;
            }
            
            currentFeedback = "";
            fingerBox.Update();
        }
        internal void setFeedback(string fb)
        {
            currentFeedback = fb;
        }
        internal void showFeedback()
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new ImageInvoker2(showFeedback));
                return;
            }
            overlayText(currentFeedback);
        }

        internal void overlayText(string text)
        {
            Graphics g = fingerBox.CreateGraphics();

            Size textSize = TextRenderer.MeasureText(text, FeedBackFont);

            if (!textSize.IsEmpty)
            {
                /* Add some space */
                textSize.Height += 1;
                textSize.Width += 1;

                int rX = ((fingerBox.Width / 2) - textSize.Width / 2);
                int rY = ((fingerBox.Height / 2) - textSize.Height / 2);

                g.FillRectangle(
                    new SolidBrush(Color.FromArgb(FeedBackTransparency, 
                                                  FeedbackBackgroundColor.R, 
                                                  FeedbackBackgroundColor.G, 
                                                  FeedbackBackgroundColor.B)), 
                    rX, 
                    rY, 
                    textSize.Width, 
                    textSize.Height);

                g.DrawString(text, 
                             FeedBackFont, 
                             new SolidBrush(FeedBackTextColor), 
                             new Rectangle(0, 0, fingerBox.Width,fingerBox.Height), 
                             stringFormat);
            }

            g.Dispose();
        }

        /* Cancel */
        private void button3_Click(object sender, EventArgs e)
        {
            try
            {
                toolkit.Cancel(selectedReader);
            }
            catch { };
            
            clearOverlay();
            SafeButtonControl(true);
            SetStatus(99);
        }

        /* Store on card */
        private void button4_Click(object sender, EventArgs e)
        {
            SmartCard SC = new SmartCard();
            IntPtr m_hCard;

            SafeButtonControl(false);

            if (MoCtemplate == null)
            {
                textBox1.Text = "No template available!";
                SafeButtonControl(true);
                SC.releasePCSC();
                return;
            }

            m_hCard = SC.connectToCard(SmartCard.SCARD_SHARE_EXCLUSIVE);
            if (m_hCard == IntPtr.Zero)
            {
                textBox1.Text = "Connection to card failed!";
                SafeButtonControl(true);
                SC.releasePCSC();
                return;
            }

            if (!SC.selectBioManager(m_hCard))
            {
                SC.disconnectCard(m_hCard);
                SC.releasePCSC();
                textBox1.Text = 
                    "Card error - Fingerprint container unaccessible";
                SafeButtonControl(true);
                return;
            }

            if (SC.beginTransaction(m_hCard) == 0)
            {
                if (!SC.writeTemplatesToCard(m_hCard,
                                             MoCtemplate.ReferenceData,
                                             MoCtemplate.BiometricHeader))
                {
                    SC.disconnectCard(m_hCard);
                    SC.releasePCSC();
                    textBox1.Text = "Card could not be personalized";
                    SafeButtonControl(true);
                    return;
                }

                SC.endTransaction(m_hCard);
            }
            else
            {
                textBox1.Text = "Card could not be personalized";
                SafeButtonControl(true);
            }

            textBox1.Text = "Template stored on card";
            SC.disconnectCard(m_hCard);
            SC.releasePCSC();
            SafeButtonControl(true);
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            try
            {
                toolkit.Cancel(selectedReader);
            }
            catch { };

            if (enrolmentThread.IsAlive)
            {
                /* Wait for thread to terminate for 5 seconds */
                if (!enrolmentThread.Join(5000))
                {
                    enrolmentThread.Abort();
                }
            }
            return;
        }
    }
}