using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог свойств смарт-карты
	///////////////////////////////////////////////////////////////////////////
	public partial class CardDialog : Form
	{
        // конструктор
		public CardDialog() { InitializeComponent(); }

        // конструктор
		public CardDialog(PCSC.ReaderScope scope, PCSC.Card card) 
        { 
            // указать имя производителя 
            InitializeComponent(); textBoxVendor.Text = card.Manufacturer ?? "N/A";

            // указать смарт-карточную подсистему
            PCSC.Windows.Provider provider = PCSC.Windows.Provider.Instance; 

            // определить номер версии
            System.Version version = card.Version; 

            // указать номер версии
            textBoxVersion.Text = (version != null) ? version.ToString() : "N/A"; 

            // указать тип смарт-карты
            textBoxModel.Text = card.Model ?? "N/A"; 

            // определить серийный номер
            byte[] serial = card.Serial; 

            // проверить наличие серийного номера
            if (serial == null || serial.Length == 0) textBoxSN.Text = "N/A";
            else { 
                // указать серийный номер
                textBoxSN.Text = Arrays.ToHexString(serial); 
            }
            // указать ATR
            textBoxATR.Text = Arrays.ToHexString(card.ATR); 

            // получить типы смарт-карты
            PCSC.Windows.CardType[] cardTypes = 
                provider.EnumerateCardTypes(scope, card.ATR, null); 

            // для всех типов смарт-карт
            foreach (PCSC.Windows.CardType carType in cardTypes)
            {
                // указать имя типа
                listBoxTypes.Items.Add(carType.Name); 
            }
		}
	}
}
