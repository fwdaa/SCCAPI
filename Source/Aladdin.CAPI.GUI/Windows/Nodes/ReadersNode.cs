using System;
using System.Windows.Forms;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Считыватели
	///////////////////////////////////////////////////////////////////////////
	internal class ReadersNode : ConsoleForm.Node
	{
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Readers.ico"; }
		// значение узла
		public override string Label { get { return Resource.NodeReaders; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
			// создать список дочерних элементов
			return new ConsoleForm.Node[] {
				new ReadersScopeNode(PCSC.ReaderScope.System), 
				new ReadersScopeNode(PCSC.ReaderScope.User  ) 
			}; 
		}
	}
}
