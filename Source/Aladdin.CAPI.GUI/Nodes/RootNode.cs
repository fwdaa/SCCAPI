using System;
using System.Windows.Forms;
using System.Globalization;
using System.Threading;
using System.Collections.Generic;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Корневой узел
	///////////////////////////////////////////////////////////////////////////
	internal class RootNode : ConsoleForm.Node
	{
		// список дочерних узлов
		private ConsoleForm.Node[] nodes; 

		// конструктор
        public RootNode(CryptoEnvironment environment) 
		{ 
			// создать список дочерних элементов
			nodes = new ConsoleForm.Node[] { 

                // добавить узел провайдеров
                new ProvidersNode(environment)  

                // добавить узел считывателей и типов смарт-карт
                , new ReadersNode(), new CardTypesNode() 
            }; 
		} 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Root.ico"; }
		// значение узла
		public override string Label { get { return "CAPI"; }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return false; }} 

		// перечислить дочерние объекты 
        public override ConsoleForm.Node[] PopulateChilds(ConsoleNode node) { return nodes; }

		// элементы контекстного меню для узла
		public override ToolStripItem[] GetContextMenuItems(ConsoleNode node) 
		{ 
			// список элементов меню
			List<ToolStripItem> items = new List<ToolStripItem>(); 

			// добавить элемент меню
			items.Add(new ToolStripMenuItem(Resource.MenuChangeLanguage, null, 
				delegate (object sender, EventArgs e) { OnChangeLanguage(node, sender, e); }
			)); 
			// вернуть список элементов
			return items.ToArray(); 
		}
		private void OnChangeLanguage(ConsoleNode node, object sender, EventArgs e)
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

			// получить текущую локализацию
			CultureInfo cultureInfo = CultureInfo.CurrentUICulture; 

			// создать диалог выбора языка
			LangDialog dialog = new LangDialog(cultureInfo); 

			// отобразить диалог выбора языка
			if (dialog.ShowDialog(mainForm) != DialogResult.OK) return; 
			
			// установить выбранный язык
			Thread.CurrentThread.CurrentUICulture = cultureInfo = dialog.CultureInfo; 

			// установить имя формы
			mainForm.Text = Resource.CommonName;

			// изменить текст элементов управления
			mainForm.ChangeLanguage(cultureInfo); 
		}
	}
}
