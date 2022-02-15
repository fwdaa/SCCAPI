using System;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог свойств смарт-карты
	///////////////////////////////////////////////////////////////////////////
	public partial class CardTypeDialog : Form
	{
        // конструктор
		public CardTypeDialog() { InitializeComponent(); }

        // конструктор
		public CardTypeDialog(PCSC.Windows.CardType cardType) 
        { 
            // получить информацию считывателя
            InitializeComponent(); 

            // получить идентификатор первичного провайдера
            Guid primaryProvider = cardType.GetPrimaryProvider(); 

            // проверить наличие идентификатора
            if (primaryProvider == Guid.Empty) textBoxPrimary.Text = "N/A"; 
            
            // указать идентификатор первичного провайдера
            else textBoxPrimary.Text = primaryProvider.ToString(); 

            // указать имена провайдеров
            textBoxCSP.Text = cardType.GetProviderCSP() ?? "N/A"; 
            textBoxKSP.Text = cardType.GetProviderKSP() ?? "N/A"; 
		}
	}
}
