using System;
using System.Windows.Forms;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог свойств апплета
	///////////////////////////////////////////////////////////////////////////
	public partial class AppletDialog : Form
	{
        // конструктор
		public AppletDialog() { InitializeComponent(); }

        // конструктор
		public AppletDialog(CAPI.PKCS11.Applet applet) 
        { 
            // получить информацию считывателя
            InitializeComponent(); SlotInfo slotInfo = applet.Store.Slot.GetInfo(); 

            // указать аппаратную версию
            textBoxReaderHV.Text = String.Format("{0}.{1}", 
                slotInfo.HardwareVersion.Major, slotInfo.HardwareVersion.Minor
            ); 
            // указать версию ПО
            textBoxReaderFV.Text = String.Format("{0}.{1}", 
                slotInfo.FirmwareVersion.Major, slotInfo.FirmwareVersion.Minor
            ); 
            // указать производителя и описание
            textBoxReaderVendor.Text = slotInfo.ManufacturerID; 
            textBoxReaderInfo  .Text = slotInfo.SlotDescription; 

            // получить информацию смарт-карты
            TokenInfo tokenInfo = applet.GetInfo(); 

            // указать аппаратную версию
            textBoxAppletHV.Text = String.Format("{0}.{1}", 
                tokenInfo.HardwareVersion.Major, tokenInfo.HardwareVersion.Minor
            ); 
            // указать версию ПО
            textBoxAppletFV.Text = String.Format("{0}.{1}", 
                tokenInfo.FirmwareVersion.Major, tokenInfo.FirmwareVersion.Minor
            ); 
            // указать производителя, модель и метку
            textBoxAppletVendor.Text = tokenInfo.ManufacturerID; 
            textBoxAppletModel .Text = tokenInfo.Model; 
            textBoxAppletLabel .Text = tokenInfo.Label; 

            // указать серийный номер
            textBoxAppletSN.Text = Arrays.ToHexString(tokenInfo.SerialNumber); 

            // общий размер открытой памяти не известен
            if (tokenInfo.TotalPublicMemory <= 0) labelTotalPublic.Text = "N/A"; 
            {
                // указать общий размер открытой памяти
                labelTotalPublic.Text = String.Format("{0} K", tokenInfo.TotalPublicMemory / 1024); 
            }
            // свободный размер открытой памяти не известен
            if (tokenInfo.FreePublicMemory == -1) labelFreePublic.Text = "N/A"; 
            {
                // указать свободный размер открытой памяти
                labelFreePublic.Text = String.Format("{0} K", tokenInfo.FreePublicMemory / 1024); 
            }
            // общий размер закрытой памяти не известен
            if (tokenInfo.TotalPrivateMemory <= 0) labelTotalPrivate.Text = "N/A"; 
            {
                // указать общий размер закрытой памяти
                labelTotalPrivate.Text = String.Format("{0} K", tokenInfo.TotalPrivateMemory / 1024); 
            }
            // свободный размер закрытой памяти не известен
            if (tokenInfo.FreePrivateMemory == -1) labelFreePrivate.Text = "N/A"; 
            {
                // указать свободный размер закрытой памяти
                labelFreePrivate.Text = String.Format("{0} K", tokenInfo.FreePrivateMemory / 1024); 
            }
            // минимальный размер пин-кода не известен
            if (tokenInfo.MinPinLen <= 0) labelMinPin.Text = "N/A"; 
            {
                // указать минимальный размер пин-кода
                labelMinPin.Text = tokenInfo.MinPinLen.ToString(); 
            }
            // максимальный размер пин-кода не известен
            if (tokenInfo.MaxPinLen <= 0) labelMaxPin.Text = "N/A"; 
            {
                // указать максимальный размер пин-кода
                labelMaxPin.Text = tokenInfo.MaxPinLen.ToString(); 
            }
            // максимальное число сеансов не известено
            if (tokenInfo.MaxSessionCount <= 0) labelMaxSessions.Text = "N/A"; 
            {
                // указать максимальное число сеансов
                labelMaxSessions.Text = tokenInfo.MaxSessionCount.ToString(); 
            }
            // максимальное число R/W сеансов не известено
            if (tokenInfo.MaxRwSessionCount <= 0) labelMaxRWSessions.Text = "N/A"; 
            {
                // указать максимальное число R/W сеансов
                labelMaxRWSessions.Text = tokenInfo.MaxRwSessionCount.ToString(); 
            }
		}
	}
}
