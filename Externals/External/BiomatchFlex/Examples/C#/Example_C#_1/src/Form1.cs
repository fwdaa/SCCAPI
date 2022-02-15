using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using PreciseBiometrics.BMFH;

namespace Example1
{
    public partial class Form1 : Form
    {
        public BioMatch toolkit = new BioMatch();
        private BM_Image image, validateImage;
        private BMFH_Template template;
        private SmartCard SC = new SmartCard();

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            /* Register callback function */
            toolkit.BiometricCallback += new BioMatch.BiometricEventHandler(BioEventHandler);
            textBox4.AppendText(SC.smartCardReader);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            int i;
            BM_Reader[] readers;

            ReaderBox.Items.Clear();

            /* Get all readers */
            toolkit.ListBiometricReaders(out readers);

            if (readers != null)
            {
                for (i = 0; i < readers.Length; i++)
                {
                    ReaderBox.Items.Add(readers[i]);
                }
                ReaderBox.SelectedIndex = 0;
            }

            textBox1.Text = "Select a reader and click CaptureImage";
        }

        private void button2_Click(object sender, EventArgs e)
        {
            BM_Reader reader;
            int quality = 0;
            BM_ImageCondition condition = 0;
            BM_ImagePresent present = 0;
            BM_ReturnCode result = BM_ReturnCode.Ok;

            QualityText.Clear();
            QualityText.Refresh();
            textBox1.Clear();
            textBox1.Refresh();
            textBox6.Clear();
            textBox6.Refresh();

            /* Check if a reader is selected */
            if (ReaderBox.SelectedIndex < 0)
            {
                MessageBox.Show("No reader is currently selected.",
                                "Error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                return;
            }

            textBox1.Text = "Place/Swipe finger on sensor.";

            reader = (BM_Reader)ReaderBox.Items[ReaderBox.SelectedIndex];

            /* Capture image */
            result = toolkit.CaptureImage(reader, 15000, out image, ImageBox);
            if (BM_ReturnCode.Ok == result)
            {
                /* Check finger status to get quality measure */
                toolkit.FingerStatus(image,
                                     out quality,
                                     out condition,
                                     out present,
                                     BM_StatusOption.Quality);

                QualityText.Text = quality.ToString();
                QualityText.Refresh();
            }
            switch (result)
            {
                case BM_ReturnCode.Ok: textBox6.Text = "OK"; break;
                case BM_ReturnCode.Cancelled: textBox6.Text = "CANCELLED"; return;
                case BM_ReturnCode.TimedOut: textBox6.Text = "TIMED OUT"; return;
                default: textBox6.Text = "SERIOUS ERROR!"; return;
            }

            textBox1.Text = "Image capture OK";
        }

        private void button3_Click(object sender, EventArgs e)
        {
            int i = 0;
            String temp;

            if (image != null)
            {

                textBox2.Clear();
                textBox2.Refresh();
                textBox1.Clear();
                textBox1.Refresh();

                /* Create a fingerprint template from the captured image */
                toolkit.CreateEnrolTemplateFromImage(image,
                                                     BM_FarLevel.Far10000,
                                                     out template);

                temp = String.Format("Biometric header: \r\n");
                textBox2.AppendText(temp);

                /* Print template */
                for (i = 0; i < template.BiometricHeader.Length; i++)
                {
                    temp = String.Format("0x{0:X2} ", template.BiometricHeader[i]);
                    textBox2.AppendText(temp);
                }

                temp = String.Format("\r\nReference data: \r\n");
                textBox2.AppendText(temp);

                for (i = 0; i < template.ReferenceData.Length; i++)
                {
                    temp = String.Format("0x{0:X2} ", template.ReferenceData[i]);
                    textBox2.AppendText(temp);
                }
                textBox1.Text = "Template created!";
            }
            else
            {
                textBox2.AppendText("No image available!");
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            BM_Reader reader;
            int quality = 0;
            BM_ImageCondition condition = 0;
            BM_ImagePresent present = 0;
            BM_ReturnCode result = BM_ReturnCode.Ok;

            textBox8.Clear();
            textBox8.Refresh();
            textBox1.Clear();
            textBox1.Refresh();
            textBox6.Clear();
            textBox6.Refresh();

            /* Check if a reader is selected */
            if (ReaderBox.SelectedIndex < 0)
            {
                MessageBox.Show("No reader is currently selected.",
                                "Error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                return;
            }
            reader = (BM_Reader)ReaderBox.Items[ReaderBox.SelectedIndex];

            /* Capture image */
            result = toolkit.CaptureImage(reader,
                                          15000,
                                          out validateImage,
                                          pictureBox2);

            if (BM_ReturnCode.Ok == result)
            {
                /* Check finger status to get quality measure */
                toolkit.FingerStatus(validateImage,
                                     out quality,
                                     out condition,
                                     out present,
                                     BM_StatusOption.Quality);

                textBox8.Text = quality.ToString();
                textBox8.Refresh();
            }
            switch (result)
            {
                case BM_ReturnCode.Ok: textBox6.Text = "OK"; break;
                case BM_ReturnCode.Cancelled: textBox6.Text = "CANCELLED"; return;
                case BM_ReturnCode.TimedOut: textBox6.Text = "TIMED OUT"; return;
                default: textBox6.Text = "SERIOUS ERROR!"; return;
            }

            textBox1.Text = "Image capture OK";
        }

        private void button5_Click(object sender, EventArgs e)
        {
            Boolean validated = false;

            textBox1.Clear();
            textBox1.Refresh();
            textBox6.Clear();
            textBox6.Refresh();

            if (validateImage != null && template != null)
            {
                /* Validate template with the validation image */
                toolkit.ValidateEnrolmentTemplateWithImage(validateImage,
                                                           template,
                                                           out validated);

                if (validated)
                {
                    textBox3.AppendText("Successfully validated template!!");
                }
                else
                {
                    textBox3.AppendText("Failed to validate template!");
                }
            }
            else
            {
                textBox3.AppendText("Not enough data available to perform validation!");
            }
            textBox3.AppendText("\r\n");
        }

        private void button6_Click(object sender, EventArgs e)
        {
            IntPtr m_hCard;

            /* Store template on smart card. */
            textBox1.Clear();
            textBox1.Refresh();
            textBox6.Clear();
            textBox6.Refresh();
            textBox4.AppendText("\r\nConnecting to card\t");
            textBox4.Refresh();

            m_hCard = SC.connectToCard(SmartCard.SCARD_SHARE_SHARED);
            if (m_hCard == IntPtr.Zero)
            {
                textBox4.AppendText("\r\nConnection failed - Card could not be personalized\t");
                return;
            }

            if (!SC.selectBioManager(m_hCard))
            {
                textBox4.AppendText(
                    "\r\nncard error - Fingerprint container unaccessible - Card could not be personalized\t");
                SC.disconnectCard(m_hCard);
                return;
            }

            if (SC.beginTransaction(m_hCard) == 0)
            {
                if (template == null ||
                    !SC.writeTemplatesToCard(m_hCard, template.ReferenceData, template.BiometricHeader))
                {
                    textBox4.AppendText("\r\nCard could not be personalized\t");
                    SC.disconnectCard(m_hCard);
                    return;
                }

                SC.endTransaction(m_hCard);
            }
            else
            {
                textBox4.AppendText("\r\nCard could not be personalized\t");
                SC.disconnectCard(m_hCard);
            }

            SC.disconnectCard(m_hCard);
            textBox4.AppendText("\r\nTemplate stored on card\t");
            textBox4.AppendText("\r\nDone!\t");
        }


        private void button7_Click(object sender, EventArgs e)
        {
            int ret = 0;
            BM_Reader reader;
            BM_ReturnCode result = BM_ReturnCode.Ok;
            BM_Image verifyMoCImage = null;
            BMFH_Template verifyMoCTemplate;
            BMFH_Template headerTemplate;
            IntPtr m_hCard;

            textBox5.Clear();
            textBox5.Refresh();
            textBox1.Clear();
            textBox1.Refresh();
            textBox6.Clear();
            textBox6.Refresh();

            /* Check if a reader is selected */
            if (ReaderBox.SelectedIndex < 0)
            {
                MessageBox.Show("No reader is currently selected.",
                                "Error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                return;
            }

            /* Open smart card in exclusive mode since we will do alternate calls 
               between biometry and smart card */
            m_hCard = SC.connectToCard(SmartCard.SCARD_SHARE_EXCLUSIVE);
            if (m_hCard == IntPtr.Zero)
            {
                textBox5.AppendText("Unable to connect to card");
                return;
            }

            if (!SC.selectBioManager(m_hCard))
            {
                textBox5.AppendText("\r\nUnable to connect select BioManager");
                SC.disconnectCard(m_hCard);
                return;
            }

            /* Retrieve the biometric header from the template on the smart card */
            byte[] publicheader = new byte[0];
            if (!SC.getHeader(m_hCard, ref publicheader))
            {
                SC.disconnectCard(m_hCard);
                textBox5.AppendText("\r\nUnable to read public header");
                return;
            }
            headerTemplate = BMFH_Template.BMFH_CreateBiometricHeaderTemplate(publicheader);

            /* Capture image */
            textBox5.AppendText("Place/swipe finger on sensor");

            /* When we have a handle to a smart card it should be used to connect to the reader.   */
            /* Since the smart card is opened with exclusive rights it is not possible to capture  */
            /* an image by just using a reader from the reader list in readerBox */
            /* (as done in function 'button6_Click'). */

            /* Create a reader with a reference to the smart card handle. */
            reader = new BM_Reader(m_hCard);
            result = toolkit.CaptureImage(reader,
                                          15000,
                                          out verifyMoCImage,
                                          pictureBox1);


            switch (result)
            {
                case BM_ReturnCode.Ok: textBox6.Text = "OK"; break; ;
                case BM_ReturnCode.Cancelled: textBox6.Text = "CANCELLED"; return;
                case BM_ReturnCode.TimedOut: textBox6.Text = "TIMED OUT"; return;
                default: textBox6.Text = "SERIOUS ERROR!"; return;
            }

            textBox6.Refresh();
            textBox1.Text = "Image capture OK";

            /* Use biometric header template from card and newly captured image 
             * to create Match-on-Card template */
            toolkit.CreateVerificationTemplateFromImage(verifyMoCImage,
                                                        headerTemplate,
                                                        out verifyMoCTemplate);

            textBox5.AppendText("\r\nPerform MoC...");

            /* Perform Match-on-Card */
            if (!SC.performMoC(m_hCard, verifyMoCTemplate.ValidationData, ref ret))
            {
                textBox5.AppendText("\r\nsending veification data to card failed.");
                SC.disconnectCard(m_hCard);
                return;
            }

            if (ret == 1)
            {
                textBox5.AppendText("\r\nMATCH OK");
            }
            else
            {
                textBox5.AppendText("\r\nMATCH FAILED");
            }

            SC.disconnectCard(m_hCard);
        }


        /* This is the callback function called by the toolkit when 
         * an image of sufficient quality has been captured. 
         * 
         * The context parameter could be any object. In this example the context parameter 
         * is used to pass the PictureBox that should present the fingerprint. */
        private void BioEventHandler(int token, Object context)
        {
            BM_Image image;
            BM_Image dummy_image;
            int dummy_quality = 0;
            BM_ImageCondition condition = 0;
            BM_ImagePresent dummy_present = 0;
            uint imageSize = 0;
            PictureBox pictureBox = (PictureBox)context;

            toolkit.CB_GetImageForViewing(token,
                                          (uint)pictureBox.Width,
                                          (uint)pictureBox.Height,
                                          (uint)((((pictureBox.Width - 1) / 4) + 1) * 4),
                                          out image,
                                          out imageSize);

            pictureBox.Image = image.ToImage();
            pictureBox.Refresh();

            /* We are only interested in the finger condition but all
             * in-parameters are required by the function. */
            toolkit.CB_FingerStatus(token,
                                    out dummy_image,
                                    out dummy_quality,
                                    out condition,
                                    out dummy_present,
                                    BM_StatusOption.Condition);

            textBox6.Text = condition.ToString();
            textBox6.Refresh();
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            SC.releasePCSC();
        }
    }
}