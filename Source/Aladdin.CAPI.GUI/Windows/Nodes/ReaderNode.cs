using System;
using System.Windows.Forms;
using System.Collections.Generic;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Считыватель
	///////////////////////////////////////////////////////////////////////////
	internal class ReaderNode : ConsoleForm.Node
	{
        // область видимости и имя
        private PCSC.ReaderScope scope; private string name;

		// конструктор
		public ReaderNode(PCSC.ReaderScope scope, string name) 
        { 
            // сохранить переданные параметры
            this.scope = scope; this.name = name; 
        } 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Reader.ico"; }
		// значение узла
		public override string Label { get { return name; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
			// создать список дочерних элементов
			List<ConsoleForm.Node> nodes = new List<ConsoleForm.Node>(); 

            // указать смарт-карточную подсистему
            PCSC.Provider provider = PCSC.Windows.Provider.Instance; 

            // создать объект считывателя
            PCSC.Reader reader = provider.GetReader(scope, name);
            try { 
                // проверить наличие считывателя
                if (reader.GetState() != PCSC.ReaderState.Card) return nodes.ToArray();

                // отккрыть сеанс со смарт-картой
                PCSC.Card card = (PCSC.Card)reader.OpenCard();
                
			    // добавить дочерний узел
			    nodes.Add(new CardNode(scope, name, card.Model)); 
            }
			catch {} return nodes.ToArray(); 
		}
	}
}
