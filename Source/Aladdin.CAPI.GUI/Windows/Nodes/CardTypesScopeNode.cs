using System;
using System.Windows.Forms;
using System.Collections.Generic;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Типы смарт-карт
	///////////////////////////////////////////////////////////////////////////
	internal class CardTypesScopeNode : ConsoleForm.Node
	{
        // область видимости и ее имя
        private PCSC.ReaderScope scope; private string name; 

		// конструктор
		public CardTypesScopeNode(PCSC.ReaderScope scope) { this.scope = scope; 

            // указать имя узла
            name = (scope == PCSC.ReaderScope.System) ? "System" : "User"; 
        } 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Scope.ico"; }
		// значение узла
		public override string Label { get { return name; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
            // указать смарт-карточную подсистему
            PCSC.Windows.Provider provider = PCSC.Windows.Provider.Instance; 

			// создать список дочерних элементов
			List<ConsoleForm.Node> nodes = new List<ConsoleForm.Node>(); 

			// перечислить типы смарт-карт
			foreach (PCSC.Windows.CardType cardType in provider.EnumerateCardTypes(scope, null, null))
			{
			    // добавить дочерний узел
			    nodes.Add(new CardTypeNode(cardType)); 
			}
			return nodes.ToArray(); 
		}
	}
}
