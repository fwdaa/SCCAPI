using System;
using System.Windows.Forms;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Типы смарт-карт
	///////////////////////////////////////////////////////////////////////////
	internal class CardTypesNode : ConsoleForm.Node
	{
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "CardTypes.ico"; }
		// значение узла
		public override string Label { get { return Resource.NodeCardTypes; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
			// создать список дочерних элементов
			return new ConsoleForm.Node[] {
				new CardTypesScopeNode(PCSC.ReaderScope.System), 
				new CardTypesScopeNode(PCSC.ReaderScope.User  ) 
			}; 
		}
	}
}
