using System;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Тип смарт-карт
	///////////////////////////////////////////////////////////////////////////
	internal class CardTypeNode : ConsoleForm.Node
	{
		// конструктор
		public CardTypeNode(PCSC.Windows.CardType cardType) 
        
            // сохранить переданные параметры
            { this.cardType = cardType; } private PCSC.Windows.CardType cardType;

		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "CardType.ico"; }
		// значение узла
		public override string Label { get { return cardType.Name; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return true; }} 

		// обработать двойное нажатие
		public override void OnProperty(ConsoleNode node, object sender, EventArgs e) 
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm;

            // показать диалог свойств
            CardTypeDialog dialog = new CardTypeDialog(cardType); dialog.ShowDialog(mainForm);
		}
	}
}
