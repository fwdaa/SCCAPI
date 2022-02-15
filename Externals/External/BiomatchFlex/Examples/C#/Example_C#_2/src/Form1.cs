using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using PreciseBiometrics.BMFH;

namespace Example2
{
    public partial class Form1 : Form
    {
        public BioMatch     toolkit = new BioMatch();
        private BM_Image    image1, image2, image3;
        private SmartCard   SC = new SmartCard();

        public Form1()
        {
            InitializeComponent();
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked)
            {
                checkBox2.Checked = false;
                checkBox3.Checked = false;
            }
        }

        private void checkBox2_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox2.Checked)
            {
                checkBox1.Checked = false;
                checkBox3.Checked = false;
            }
        }

        private void checkBox3_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox3.Checked)
            {
                checkBox1.Checked = false;
                checkBox2.Checked = false;
            }
        }

        /* Register biometric callback */
        private void Form1_Load(object sender, EventArgs e)
        {
            toolkit.BiometricCallback += new BioMatch.BiometricEventHandler(BioEventHandler);
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
            }
        }

        private void BioEventHandler(int token, Object context)
        {
            BM_Image image;
            PictureBox pictureBox = (PictureBox)context;
            BM_ImageCondition condition;
            BM_ImagePresent present;
            int quality;
            
            toolkit.CB_FingerStatus(token,
                out image,
                out quality,
                out condition,
                out present,
                BM_StatusOption.Image);

            pictureBox.Image = image.ToImage();
            pictureBox.Refresh();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            captureImage(pictureBox1, textBox1, out image1);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            captureImage(pictureBox2, textBox2, out image2);
        }

        private void button4_Click(object sender, EventArgs e)
        {
            captureImage(pictureBox3, textBox3, out image3);
        }

        private void captureImage(PictureBox picBox, 
                                  TextBox textBox, 
                                  out BM_Image image)
        {
            BM_Reader reader;
            int quality = 0;
            BM_ImageCondition dummy_condition = 0;
            BM_ImagePresent dummy_present = 0;
            BM_ReturnCode result = BM_ReturnCode.Ok;
            image = null;

            /* Check if a reader is selected */
            if (comboBox1.SelectedIndex < 0)
            {
                MessageBox.Show("No reader is currently selected.",
                                "Error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Error);
                return;
            }

            reader = (BM_Reader)comboBox1.Items[comboBox1.SelectedIndex];

            /* Capture 1st image */
            result = toolkit.CaptureImage(reader,
                                          15000,
                                          out image,
                                          picBox);

            if (BM_ReturnCode.Ok == result)
            {
                /* Retreive the quality of the image */
                toolkit.FingerStatus(image,
                                     out quality,
                                     out dummy_condition,
                                     out dummy_present,
                                     BM_StatusOption.Quality);
            }

            textBox.Text = quality.ToString();
            textBox.Refresh();
        }

        private void button5_Click(object sender, EventArgs e)
        {
            BM_Image        enrollImage = null;
            BMFH_Template   template;
            IntPtr          m_hCard;

            textBox5.Clear();
            textBox5.Refresh();

            if (checkBox1.Checked)
            {
                enrollImage = image1;
            }
            else if (checkBox2.Checked)
            {
                enrollImage = image2;
            }
            else if (checkBox3.Checked)
            {
                enrollImage = image3;
            }

            if (enrollImage != null)
            {
                /* Create template from image */
                toolkit.CreateEnrolTemplateFromImage(enrollImage,
                                                     BM_FarLevel.Far10000,
                                                     out template);
            }
            else
            {
                textBox5.Text = "No image selected!";
                return;
            }

            m_hCard = SC.connectToCard(SmartCard.SCARD_SHARE_SHARED);
            if (m_hCard == IntPtr.Zero)
            {
                textBox5.Text = 
                    "Connection failed - Card could not be personalized";
                return;
            }

            if (!SC.selectBioManager(m_hCard))
            {
                textBox5.Text = 
                    "card error - Fingerprint container unaccessible - Card could not be personalized";
                SC.disconnectCard(m_hCard);
                return;
            }

            if (SC.beginTransaction(m_hCard) == 0)
            {

                if (template == null ||
                    !SC.writeTemplatesToCard(m_hCard, template.ReferenceData, template.BiometricHeader))
                {
                    textBox5.Text = "Card could not be personalized";
                    SC.disconnectCard(m_hCard);
                    return;
                }

                SC.endTransaction(m_hCard);
            }
            else
            {
                textBox5.Text = "Card could not be personalized";
            }

            SC.disconnectCard(m_hCard);
            textBox5.Text = "Enrollment completed!";
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            SC.releasePCSC();
        }
    }
}