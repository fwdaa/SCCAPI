using System;
using System.Windows.Forms;
using System.Collections.Generic;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Криптографический провайдер
	///////////////////////////////////////////////////////////////////////////
	internal class ProviderScopeNode : ConsoleForm.Node
	{
		private CryptoEnvironment  environment;    // криптографическая среда
		private CryptoProvider     provider;	   // информация о провайдере
		private Scope              scope;	       // область видимости
		
		// конструктор
		public ProviderScopeNode(CryptoEnvironment environment, CryptoProvider provider, Scope scope) 
		{ 
			// сохранить переданные данные
			this.environment = environment; this.provider = provider; this.scope = scope; 
		} 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Scope.ico"; }
		// значение узла
		public override string Label 
        { 
		    // значение узла
            get { return (scope.Equals(Scope.System)) ? "System" : "User"; }
        }
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// способ сортировки
        public override SortOrder ChildSortOrder { get { return SortOrder.Ascending; }}

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) 
		{ 
			// создать список дочерних элементов
			List<ConsoleForm.Node> nodes = new List<ConsoleForm.Node>(); 

			// перечислить хранилища контейнеров
			foreach (string storeName in provider.EnumerateStores(scope))
			try {
                // открыть хранилище
                using (SecurityStore store = provider.OpenStore(scope, storeName))
                {
				    // добавить дочерний узел
				    nodes.Add(new StoreNode(environment, provider, store.GetType(), store.Info)); 
                }
			}
			catch {} return nodes.ToArray(); 
		}
	}
}
