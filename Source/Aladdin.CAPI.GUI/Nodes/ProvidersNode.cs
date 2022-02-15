using System;
using System.Collections.Generic;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Узел провайдеров
	///////////////////////////////////////////////////////////////////////////
	internal class ProvidersNode : ConsoleForm.Node
	{
		// список дочерних узлов
		private ConsoleForm.Node[] nodes; 

		// конструктор
        public ProvidersNode(CryptoEnvironment environment, IEnumerable<CryptoProvider> providers) 
		{ 
			// создать список дочерних элементов
			List<ConsoleForm.Node> nodes = new List<ConsoleForm.Node>(); 

			// для всех провайдеров
			foreach (CryptoProvider provider in providers)
			{
				// добавить узел провайдера
				nodes.Add(new ProviderNode(environment, provider)); 
			}
			// сохранить список узлов
			this.nodes = nodes.ToArray(); 
		} 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Providers.ico"; }
		// значение узла
		public override string Label { get { return Resource.NodeProviders; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) { return nodes; }
	}
}
