using System;
using System.Windows.Forms;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	internal class ProviderNode : ConsoleForm.Node
	{
		private CryptoEnvironment environment;	// криптографическая среда
		private CryptoProvider	  provider;		// информация о провайдере
		
		// конструктор
		public ProviderNode(CryptoEnvironment environment, CryptoProvider provider) 
		{ 
			// сохранить переданные данные
			this.environment = environment; this.provider = provider; 
		} 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Provider.ico"; }
		// значение узла
		public override string Label { get { return provider.Name; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
			// создать список дочерних элементов
			return new ConsoleForm.Node[] {
				new ProviderScopeNode(environment, provider, Scope.System), 
				new ProviderScopeNode(environment, provider, Scope.User  ) 
			}; 
		}
	}
}
