using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.IO;
using System.Windows.Forms;
using PreciseBiometrics.BMFH;

namespace Example4
{
    public partial class Form1 : Form
    {
        public BioMatch toolkit = new BioMatch();
        BM_Image fromWSQimage = null;
        BM_Image fromBMPimage = null;

        public Form1()
        {
            InitializeComponent();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (openBMPFileDialog1.ShowDialog() == DialogResult.OK)
            {
                byte[] fileData = File.ReadAllBytes(openBMPFileDialog1.FileName);
                try
                {
                    toolkit.ImportImageFromBitmap(fileData, out fromBMPimage);
                }
                catch 
                {
                    return;
                }
                if (fromBMPimage != null)
                {
                    bmpPicture.Image = fromBMPimage.ToImage();
                }
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (openWSQFileDialog1.ShowDialog() == DialogResult.OK)
            {
                byte[] fileData = File.ReadAllBytes(openWSQFileDialog1.FileName);
                try
                {
                    toolkit.ImportImageFromWSQ(fileData, out fromWSQimage);
                }
                catch 
                {
                    return;
                }
                if (fromWSQimage != null)
                {
                    wsqPicture.Image = fromWSQimage.ToImage();
                }
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (fromBMPimage != null &&
                saveToBmpDialog1.ShowDialog() == DialogResult.OK)
            {
                byte[] bmpFile;
                try
                {
                    toolkit.ExportImageToBitmap(fromBMPimage, out bmpFile);
                }
                catch 
                {
                    return;
                }
                FileStream fs = File.Create(saveToBmpDialog1.FileName);
                fs.Write(bmpFile, 0, bmpFile.Length);
                fs.Close();
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (fromWSQimage != null &&
                saveToWsqFileDialog1.ShowDialog() == DialogResult.OK)
            {
                byte[] wsqFile;
                try
                {
                    toolkit.ExportImageToWSQ(fromWSQimage, out wsqFile);
                }
                catch 
                {
                    return;
                }

                FileStream fs = File.Create(saveToWsqFileDialog1.FileName);
                fs.Write(wsqFile, 0, wsqFile.Length);
                fs.Close();
            }
        }
    }
}