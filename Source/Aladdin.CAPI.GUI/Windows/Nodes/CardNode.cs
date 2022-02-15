using System;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Смарт-карта
	///////////////////////////////////////////////////////////////////////////
	internal class CardNode : ConsoleForm.Node
	{
        // область видимости, имя считывателя и смарт-карты
        private PCSC.ReaderScope scope; private string readerName; private string name;

		// конструктор
		public CardNode(PCSC.ReaderScope scope, string readerName, string name) 
        { 
            // сохранить переданные параметры
            this.scope = scope; this.readerName = readerName; this.name = name;
        } 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Card.ico"; }
		// значение узла
		public override string Label { get { return name; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return true; }} 

		// обработать двойное нажатие
		public override void OnProperty(ConsoleNode node, object sender, EventArgs e) 
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm;

            // указать смарт-карточную подсистему
            PCSC.Provider provider = PCSC.Windows.Provider.Instance; 

            // создать объект считывателя
            PCSC.Reader reader = provider.GetReader(scope, readerName); 
            try { 
                // открыть сеанс со смарт-картой
                PCSC.Card card = (PCSC.Card)reader.OpenCard(); 
                
		        // создать диалог свойств
		        CardDialog dialog = new CardDialog(scope, card); 

		        // показать диалог
		        dialog.ShowDialog(mainForm); 
            }
            catch {}
		}
	}
}
