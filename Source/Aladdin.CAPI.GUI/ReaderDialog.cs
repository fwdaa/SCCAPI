using System;
using System.Windows.Forms;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог свойств считывателя
	///////////////////////////////////////////////////////////////////////////
	public partial class ReaderDialog : Form
	{
        // конструктор
		public ReaderDialog() { InitializeComponent(); }

        // конструктор
		public ReaderDialog(CAPI.PKCS11.Token token) 
        { 
            // получить информацию считывателя
            InitializeComponent(); SlotInfo slotInfo = token.Slot.GetInfo(); 

            // указать аппаратную версию
            textBoxHV.Text = String.Format("{0}.{1}", 
                slotInfo.HardwareVersion.Major, slotInfo.HardwareVersion.Minor
            ); 
            // указать версию ПО
            textBoxFV.Text = String.Format("{0}.{1}", 
                slotInfo.FirmwareVersion.Major, slotInfo.FirmwareVersion.Minor
            ); 
            // указать производителя и описание
            textBoxVendor.Text = slotInfo.ManufacturerID; 
            textBoxInfo  .Text = slotInfo.SlotDescription;
		}
	}
}
