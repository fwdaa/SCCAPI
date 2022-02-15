using System;
using System.Reflection;
using System.Drawing;
using System.ComponentModel;
using System.Globalization;
using System.Windows.Forms;
using System.Collections.Generic;

namespace Aladdin.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Основное окно консоли
	///////////////////////////////////////////////////////////////////////////
	public partial class ConsoleForm : Form
	{
        // используемый прогресс-бар
   		private ProgressBar progressBar;

		// корневой и последний выделенный узел
		private ConsoleNode rootNode; private ConsoleNode selectedNode; 

		// конструктор
		public ConsoleForm() { InitializeComponent(); 

			// установить размер панели статус-бара
			applicationStatusBar.Panels[1].AutoSize = StatusBarPanelAutoSize.Spring;  

            // создать прогресс-бар
            progressBar = new ProgressBar(); progressBar.BringToFront();

			// позиционировать прогресс-бар на статус-баре
			progressBar.Location = new Point(applicationStatusBar.Panels[0].Width + 2, 2); 

            // установить размер прогресс-бара
			progressBar.Width  = applicationStatusBar.Width  - progressBar.Location.X; 
			progressBar.Height = applicationStatusBar.Height - progressBar.Location.Y; 

			// установить границы прогресс-бара
			progressBar.Minimum = 0; progressBar.Maximum = 100;

            // указать стиль прогресс-бара
            progressBar.Style = ProgressBarStyle.Continuous; progressBar.Visible = false; 

			// прикрепить прогресс-бар к статус-бару
			applicationStatusBar.Controls.Add(progressBar);
		} 
        // установить текст в статус-баре
		public void SetText(string text) 
		{ 
			// проверить наличие сообщения
			if (String.IsNullOrEmpty(text)) text = Resource.StatusReady; 

			// установить сообщение
			mainStatusBarPanel.Text = text; 
		}
		// изменить язык
		public virtual void ChangeLanguage(CultureInfo culture) 
		{
			// получить описание ресурсов
			ComponentResourceManager manager = new ComponentResourceManager(typeof(ConsoleForm));

			// установить значения элементов меню верхнего уровня
			fileMenu  .Text = manager.GetString("fileMenu.Text"  , culture);
			actionMenu.Text = manager.GetString("actionMenu.Text", culture);
			viewMenu  .Text = manager.GetString("viewMenu.Text"  , culture);
			helpMenu  .Text = manager.GetString("helpMenu.Text"  , culture);

			// установить значения элементов нижнего уровня
			exitMenuItem      .Text = manager.GetString("exitMenuItem.Text"      , culture);
			largeIconsMenuItem.Text = manager.GetString("largeIconsMenuItem.Text", culture);
			smallIconsMenuItem.Text = manager.GetString("smallIconsMenuItem.Text", culture);
			listMenuItem	  .Text = manager.GetString("listMenuItem.Text"      , culture);
			aboutMenuItem	  .Text = manager.GetString("aboutMenuItem.Text"     , culture);

			// переустановить сообщение об отсутствии элементов
			objectListView.EmptyMessage = Resource.EmptyListView;

			// обновить содержимое списка элементов
			if (objectListView.Items.Count == 0) objectListView.Refresh(); 

			// сбросить строку статус-бара
			mainStatusBarPanel.Text = Resource.StatusReady; 
		}
		// корневой и последний выделенный узел
		public ConsoleNode RootNode     { get { return rootNode;     }}
		public ConsoleNode SelectedNode { get { return selectedNode; }}

        // окно отображения объектов        
		public TreeView TreeView { get { return objectTreeView; }}

        // окно отображения объектов        
		public ListView ListView { get { return objectListView; }}

        // прогресс-бар
        public ProgressBar ProgressBar { get { return progressBar; }}

		///////////////////////////////////////////////////////////////////////
		// Переопределяемые функции
		///////////////////////////////////////////////////////////////////////
		protected virtual Icon GetIcon(string name) 
		{ 
			// определить исполняемую сборку
			Assembly assembly = Assembly.GetExecutingAssembly();

			// определить имя ресурса
			string resource = assembly.GetName().Name + "." + name;

			// вернуть найденный ресурс
			return new Icon(assembly.GetManifestResourceStream(resource)); 
		} 
		// корневой узел
		protected virtual Node GetRootNode() { return new Node(); } 

		// имя формы
		protected virtual String GetName() { return String.Empty; } 

		// содержимое меню Help
		protected virtual ToolStripItem[] GetHelpItems() 
		{ 
			// содержимое меню Help
			return new ToolStripItem[0]; 
		}  
		///////////////////////////////////////////////////////////////////////
		// Инициализация основного окна
		///////////////////////////////////////////////////////////////////////
		protected virtual void OnLoad(object sender, EventArgs e)
		{
			// получить содержимое меню Help
			ToolStripItem[] helpItems = GetHelpItems(); Array.Resize(ref helpItems, helpItems.Length + 1); 

			// сохранить меню About
			helpItems[helpItems.Length - 1] = helpMenu.DropDownItems[0]; 

			// переустановить меню Help
			helpMenu.DropDownItems.Clear(); helpMenu.DropDownItems.AddRange(helpItems); 

			// создать корневой узел
            rootNode = new ConsoleNode(this, GetRootNode()); selectedNode = null; 

            // установить заголовок формы
			objectListView.EmptyMessage = Resource.EmptyListView; Text = GetName(); 

			// создать корневой узел
            Activate(); objectTreeView.AfterSelect -= OnAfterSelectObjectsTree;

			// установить узел в графическом интерфейсе
			objectTreeView.Nodes.Clear(); objectTreeView.Nodes.Add(rootNode.TreeNode);

			// выделить узел
			objectTreeView.SelectedNode = rootNode.TreeNode; selectedNode = rootNode;

			// установить обработчик событий
            objectTreeView.AfterSelect += OnAfterSelectObjectsTree; 
 
			// перечислить дочерние узлы
            RefreshNode(rootNode); rootNode.TreeNode.Expand();

            // установить размер текста
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 
        }
		protected virtual void OnResize(object sender, EventArgs e)
		{
			// установить границу статус-бара
			applicationStatusBar.SizingGrip = (FormWindowState.Maximized != WindowState);

			// позиционировать прогресс-бар на статус-баре
			progressBar.Location = new Point(applicationStatusBar.Panels[0].Width + 2, 2); 

            // установить размер прогресс-бара
			progressBar.Width  = applicationStatusBar.Width  - progressBar.Location.X; 
			progressBar.Height = applicationStatusBar.Height - progressBar.Location.Y; 

            // установить размер текста
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 
		}
		///////////////////////////////////////////////////////////////////////
		// Обработчики фиксированных событий
		///////////////////////////////////////////////////////////////////////
		private void OnAbout(object sender, EventArgs e)
		{
			// определить номер версии приложения
			string version = Application.ProductVersion; 

			// сформировать информацию о приложении
			string message = String.Format("{0}. {1} {2}.\r\n{3}",
				Text, Resource.CommonVersion, version, Resource.CommonCopyright
			);
			// вывести информацию о приложении
			MessageBox.Show(this, message, Resource.CommonAbout);
		}
		private void OnClickExitMenu(object sender, EventArgs e)
		{
			Close(); // закрыть окно
		}
		private void OnClickLargeIconsMenu(object sender, EventArgs e)
		{
			// переустановить выбранный способ отображения
			objectListView.View = View.LargeIcon;

            // установить размер текста
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 

			// установить выбранный пункт меню
			largeIconsMenuItem.Checked = true;
			smallIconsMenuItem.Checked = false; 
			listMenuItem      .Checked = false; 
		}
		private void OnClickSmallIconsMenu(object sender, EventArgs e)
		{
			// переустановить выбранный способ отображения
			objectListView.View = View.SmallIcon;

            // установить размер текста
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 

			// переустановить выбранный способ отображения
			largeIconsMenuItem.Checked = false;
			smallIconsMenuItem.Checked = true; 
			listMenuItem      .Checked = false; 
		}
		private void OnClickListMenu(object sender, EventArgs e)
		{
			// переустановить выбранный способ отображения
			objectListView.View = View.List;

            // установить размер текста
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 

			// переустановить выбранный способ отображения
			largeIconsMenuItem.Checked = false;
			smallIconsMenuItem.Checked = false; 
			listMenuItem      .Checked = true; 
		}
        ///////////////////////////////////////////////////////////////////////
        // Обработчики событий узлов
        ///////////////////////////////////////////////////////////////////////
		internal void SelectNode(ConsoleNode node)
		{
			// выделить элемент 
			if (!node.Node.IsLeaf) objectTreeView.SelectedNode = node.TreeNode; 
		}
		internal ConsoleNode[] RefreshNode(ConsoleNode node)
		{
			List<ConsoleNode> childNodes = new List<ConsoleNode>(); 

			// обновить иконку и метку
			InvalidateNode(node); if (node.Node.IsLeaf) return childNodes.ToArray(); 

            // создать список имен выделенных элементов
            List<String> listSelectedLabels = new List<String>(); 

            // для всех выделенных узлов
            foreach (ListViewItem listViewItem in objectListView.SelectedItems)
            {
                // получить выделенный элемент
                ConsoleNode consoleNode = (ConsoleNode)listViewItem.Tag; 

                // сохранить имя выделенного узла
                listSelectedLabels.Add(consoleNode.Node.Label); 
            }
			// начать обновление пользовательского интерфейса
			objectTreeView.BeginUpdate(); objectListView.BeginUpdate();

			// изменить форму курсора
			Cursor cursor  = Cursor.Current; Cursor.Current = Cursors.WaitCursor;
			try {
				// очистить список дочерних элементов
				node.TreeNode.Nodes.Clear(); 

				// очистить список отображаемых элементов
				if (selectedNode == node) objectListView.Items.Clear();

				// обновить дочерние элементы
				Node[] childs = node.Node.PopulateChilds(node); 

                // выполнить сортировку
                if (node.Node.ChildSortOrder == SortOrder.Ascending ) Array.Sort   (childs);
                if (node.Node.ChildSortOrder == SortOrder.Descending) Array.Reverse(childs); 
                
				// для каждого дочернего элемента
				foreach (Node child in childs)
				{
					// добавить дочерний объект
					ConsoleNode childNode = new ConsoleNode(node, child);

					// добавить узел в иерархическое дерево
					if (!child.IsLeaf) node.TreeNode.Nodes.Add(childNode.TreeNode);

					// добавить элемент в список элементов
					if (selectedNode == node) objectListView.Items.Add(childNode.ListNode);

					// обновить иконку и метку для нового узла
					InvalidateNode(childNode); childNodes.Add(childNode); 

                    // для ранее выделенного элемента
                    if (listSelectedLabels.Contains(child.Label))
                    {
                        // выделить ранее выделенный элемент
                        childNode.ListNode.Focused  = true; 
                        childNode.ListNode.Selected = true; 
                    }
				}
				return childNodes.ToArray(); 
			}
			// при ошибке 
			catch (Exception ex) 
            {
                // вывести описание ошибки
				ErrorDialog.Show(this, ex); return childNodes.ToArray(); 
            }
			// восстановить форму курсора
			finally { Cursor.Current = cursor; 
			
				// завершить обновление пользовательского интерфейса
				objectListView.EndUpdate(); objectTreeView.EndUpdate();
			}
		}
		private void InvalidateNode(ConsoleNode node)
		{
			// получить списки иконок графического интерфейса
			ImageList smallImagesTree = objectTreeView.ImageList;
			ImageList smallImagesList = objectListView.SmallImageList;
			ImageList largeImagesList = objectListView.LargeImageList;

            // получить имя иконки
            string iconName = node.Node.GetIcon(node); 

			// при отсутствии иконки в списке
			if (!smallImagesTree.Images.ContainsKey(iconName))
			{
				// получить требуемую иконку
				Icon smallIcon = new Icon(GetIcon(iconName), 16, 16);

				// добавить иконку в список
				smallImagesTree.Images.Add(iconName, smallIcon.ToBitmap());
			}
			// при отсутствии иконки в списке
			if (!smallImagesList.Images.ContainsKey(iconName))
			{
				// получить требуемую иконку
				Icon smallIcon = new Icon(GetIcon(iconName), 16, 16);

				// добавить иконку в список
				smallImagesList.Images.Add(iconName, smallIcon.ToBitmap());
			}
			// при отсутствии иконки в списке
			if (!largeImagesList.Images.ContainsKey(iconName))
			{
				// получить требуемые иконки
				Icon largeIcon = new Icon(GetIcon(iconName), 32, 32);

				// добавить иконку в список
				largeImagesList.Images.Add(iconName, largeIcon.ToBitmap());
			}
			// установить иконку для элемента
			node.TreeNode.SelectedImageKey = iconName;

			// установить иконку для элемента
			node.TreeNode.ImageKey = iconName; node.ListNode.ImageKey = iconName;

			// установить метку для элемента
			node.TreeNode.Text = node.Node.Label; node.ListNode.Text = node.Node.Label;
		}
		private void DeleteNode(ConsoleNode node)
		{
            // удалить узел из иерархического дерева
            if (!node.Node.IsLeaf) node.TreeNode.Remove();

            // при выделенном родительском узле
            if (selectedNode == node.Parent)
            {
                // удалить элемент из списка элементов
	            objectListView.Items.Remove(node.ListNode);
            }
        }
		private void OnNodeDoubleClick(ConsoleNode node, object sender, EventArgs e)
		{
			// вызвать обработчик события
			if (node.Node.IsLeaf) node.Node.OnProperty(node, sender, e); 
			else {
				// развернуть или свернуть дочерние элементы
				if (node.TreeNode.IsExpanded) node.TreeNode.Collapse(); else node.TreeNode.Expand();

				// выделить элемент в иерархическом дереве
				objectTreeView.SelectedNode = node.TreeNode; 
			}
		}
		private void OnNodeRename(ConsoleNode node, object sender, EventArgs e)
		{
			// установить обработчик завершения редактирования
			objectListView.AfterLabelEdit += OnNodeRenameEnd;

			// проверить число выбранных узлов
			if (objectListView.SelectedItems.Count != 1) return;

			// начать редактирование
			objectListView.LabelEdit = true; objectListView.SelectedItems[0].BeginEdit();
		}
		private void OnNodeRenameEnd(object sender, LabelEditEventArgs e)
		{
			// отменить обработчик завершения редактирования
			objectListView.AfterLabelEdit -= OnNodeRenameEnd; objectListView.LabelEdit = false;

			// определить узел редактирования
			ConsoleNode node = (ConsoleNode)objectListView.Items[e.Item].Tag;

			// проверить изменение текста
			if (e.Label == null || node.Node.Label == e.Label) return; string label = e.Label; 
            
            // изменить регистр символов
            if (node.Node.Casing == CharacterCasing.Lower) label = label.ToLower(); 
            if (node.Node.Casing == CharacterCasing.Upper) label = label.ToUpper(); 

			// изменить отображаемое имя элемента
			try { node.Node.SetLabel(node, label); node.ListNode.Text = label; e.CancelEdit = false; }

			// при ошибке вывести ее описание
			catch (Exception ex) { e.CancelEdit = true; Aladdin.GUI.ErrorDialog.Show(this, ex); }
		}
		private void OnNodesDelete(ConsoleNode[] nodes, object sender, EventArgs e)
		{
		    // удалить объекты
    		try { nodes[0].Parent.Node.DeleteChilds(nodes[0].Parent, nodes); }

			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(this, ex); }
		}
		private void OnNodeHelp(ConsoleNode node, object sender, EventArgs e)
		{
			// отобразить справку
			node.Node.OnHelp(node, sender, e);
		}
		///////////////////////////////////////////////////////////////////////
		// Добавление обработчиков в зависимости от контекста
		///////////////////////////////////////////////////////////////////////
		private void FillListViewMenu(ToolStripItemCollection menuItems, ConsoleNode node, bool hasViewMenu)
		{
			if (ActiveControl == objectTreeView)
			{
				menuItems.Add(new ToolStripMenuItem(
					Resource.MenuOpen, null, 
					delegate(object sender, EventArgs e) { 
						OnNodeDoubleClick(node, sender, e); 
					}
				));
				menuItems[0].Select();
			}
			else if (objectListView.SelectedItems.Count == 1) 
			{
				string name = node.Node.IsLeaf ? 
					Resource.MenuProperties : Resource.MenuOpen; 

				menuItems.Add(new ToolStripMenuItem(name, null, 
					delegate(object sender, EventArgs e) { 
						OnNodeDoubleClick(node, sender, e); 
					}
				));
				menuItems[0].Select();
			}
			ToolStripItem[] contextMenuItems = node.Node.GetContextMenuItems(node);
			if (contextMenuItems.Length > 0)
			{
                if (menuItems.Count > 0) menuItems.Add(new ToolStripSeparator());

				menuItems.AddRange(contextMenuItems);
			}
			if (node.Node.CanEdit || node.Node.CanDelete) 
			{
                if (menuItems.Count > 0) menuItems.Add(new ToolStripSeparator());

				if (node.Node.CanEdit) {
					menuItems.Add(new ToolStripMenuItem(
                        Resource.MenuRename, null, 
    					delegate(object sender, EventArgs e) { 
                            OnNodeRename(node, sender, e); 
                        }
					));
				}
				if (node.Node.CanDelete) {
				    menuItems.Add(new ToolStripMenuItem(
					    Resource.MenuDelete, null, 
			            delegate (object sender, EventArgs e) {
						    OnNodesDelete(new ConsoleNode[] {node}, sender, e); 
                        }
				    ));
                }
			}
			if (hasViewMenu)
			{
                if (menuItems.Count > 0) menuItems.Add(new ToolStripSeparator());

				ToolStripMenuItem copyLargeIconsMenuItem = new ToolStripMenuItem(
					largeIconsMenuItem.Text, null, 
					OnClickLargeIconsMenu, largeIconsMenuItem.Name
				);
				copyLargeIconsMenuItem.Checked = largeIconsMenuItem.Checked; 
				menuItems.Add(copyLargeIconsMenuItem); 

				ToolStripMenuItem copySmallIconsMenuItem = new ToolStripMenuItem(
					smallIconsMenuItem.Text, null, 
					OnClickSmallIconsMenu, smallIconsMenuItem.Name
				);
				copySmallIconsMenuItem.Checked = smallIconsMenuItem.Checked; 
				menuItems.Add(copySmallIconsMenuItem); 

				ToolStripMenuItem copyListMenuItem = new ToolStripMenuItem(
					listMenuItem.Text, null, 
					OnClickListMenu, listMenuItem.Name
				);
				copyListMenuItem.Checked = listMenuItem.Checked; 
				menuItems.Add(copyListMenuItem); 
			}
			if (ActiveControl == objectTreeView)
			{
                if (menuItems.Count > 0) menuItems.Add(new ToolStripSeparator());

				menuItems.Add(new ToolStripMenuItem(
					Resource.MenuRefresh, null, 
					delegate(object sender, EventArgs e) {
						RefreshNode(node);
					}
				));
			}
			else if (objectListView.SelectedItems.Count == 0)
			{
                if (menuItems.Count > 0) menuItems.Add(new ToolStripSeparator());

				menuItems.Add(new ToolStripMenuItem(
					Resource.MenuRefresh, null, 
					delegate(object sender, EventArgs e) {
						RefreshNode(node);
					}
				));
			}
//          if (menuItems.Count > 0) menuItems.Add(new ToolStripSeparator());
//
//            menuItems.Add(new ToolStripMenuItem(
//				Resource.MenuHelp, null, 
//				delegate (object sender, EventArgs e) {
//                   OnNodeHelp(node, sender, e); 
//                }
//			));
		}
		private void FillListViewMenu(ToolStripItemCollection menuItems, ConsoleNode[] nodes)
		{
            foreach (ConsoleNode node in nodes)
            {
                if (!node.Node.CanDelete) return;
            }
            menuItems.Add(new ToolStripMenuItem(
				Resource.MenuDelete, null, 
		        delegate (object sender, EventArgs e) {
					OnNodesDelete(nodes, sender, e); 
                }
			));
		}
		private void OnPopupActionMenu(object sender, EventArgs e)
		{
			if (ActiveControl != objectTreeView &&
				ActiveControl != objectListView) return;

			actionMenu.DropDownItems.Clear();
			if (ActiveControl == objectTreeView || objectListView.SelectedItems.Count == 0)
			{
				ConsoleNode node = (ConsoleNode)objectTreeView.SelectedNode.Tag;
				FillListViewMenu(actionMenu.DropDownItems, node, false);
			}
			else if (objectListView.SelectedItems.Count == 1)
			{
				ConsoleNode node = (ConsoleNode)objectListView.SelectedItems[0].Tag;
				FillListViewMenu(actionMenu.DropDownItems, node, false);
			}
			else if (objectListView.SelectedItems.Count > 1)
			{
                List<ConsoleNode> nodes = new List<ConsoleNode>(); 
                foreach (ListViewItem item in objectListView.SelectedItems)
				{ 
                    nodes.Add((ConsoleNode)item.Tag); 
				}
				FillListViewMenu(actionMenu.DropDownItems, nodes.ToArray());
			}
		}
		private void OnPopupContextMenu(object sender, CancelEventArgs e)
		{
			if (ActiveControl != objectTreeView &&
				ActiveControl != objectListView) { e.Cancel = true; return; }

			contextMenu.Items.Clear(); e.Cancel = false; 
			if (ActiveControl == objectTreeView || objectListView.SelectedItems.Count == 0)
			{
				ConsoleNode node = (ConsoleNode)objectTreeView.SelectedNode.Tag;
				FillListViewMenu(contextMenu.Items, node, node == selectedNode);
			}
			else if (objectListView.SelectedItems.Count == 1)
			{
				ConsoleNode node = (ConsoleNode)objectListView.SelectedItems[0].Tag;
				FillListViewMenu(contextMenu.Items, node, node == selectedNode);
			}
			else if (objectListView.SelectedItems.Count > 1)
			{
                List<ConsoleNode> nodes = new List<ConsoleNode>(); 
                foreach (ListViewItem item in objectListView.SelectedItems)
				{ 
                    nodes.Add((ConsoleNode)item.Tag); 
				}
				FillListViewMenu(contextMenu.Items, nodes.ToArray());
			}

		}
		///////////////////////////////////////////////////////////////////////
		// Обработчики событий иерархического дерева узлов
		///////////////////////////////////////////////////////////////////////
		private Point GetContextPointObjectsTree()
		{
			Point point = objectTreeView.SelectedNode.Bounds.Location;
			point.Offset(0, objectTreeView.SelectedNode.Bounds.Height);
			return point; 
		}
		private void OnMouseUpObjectsTree(object sender, MouseEventArgs e)
		{
			if (e.Button != MouseButtons.Right) return;

			TreeNode node = objectTreeView.GetNodeAt(e.X, e.Y);
			if (node == null) contextMenu.Show(objectTreeView, new Point(e.X, e.Y));
			else {
				Rectangle bounds = node.Bounds;
				if (e.X < bounds.X || bounds.Right < e.X)
					contextMenu.Show(objectTreeView, new Point(e.X, e.Y));
				else { 
					TreeNode selectedNode = objectTreeView.SelectedNode;
					objectTreeView.SelectedNode = node;
					contextMenu.Show(objectTreeView, new Point(e.X, e.Y));
					objectTreeView.SelectedNode = selectedNode;
				}
			}
		}
		private void OnKeyDownObjectsTree(object sender, KeyEventArgs e)
		{
			if (objectTreeView.SelectedNode == null) return;
			if (e.KeyData != (Keys.F10 | Keys.Shift)) return;

			Point point = GetContextPointObjectsTree();
			contextMenu.Show(objectTreeView, point); e.Handled = true;
		}
		private void OnKeyUpObjectsTree(object sender, KeyEventArgs e)
		{
			if (objectTreeView.SelectedNode == null) return;
			if (e.KeyData != Keys.Apps) return;

			Point point = GetContextPointObjectsTree();
			contextMenu.Show(objectTreeView, point); e.Handled = true;
		}
		private void OnAfterSelectObjectsTree(object sender, TreeViewEventArgs e)
		{
			selectedNode = e.Node.Tag as ConsoleNode; RefreshNode(selectedNode); 
		}
		///////////////////////////////////////////////////////////////////////
		// Обработчики событий списка узлов
		///////////////////////////////////////////////////////////////////////
		private Point GetContextPointObjectsList(ListViewItem item)
		{
			Point point = item.Bounds.Location;
			if (objectListView.View != View.LargeIcon)
			{
				point.Offset(item.ImageList.ImageSize.Height / 2,
					item.ImageList.ImageSize.Width / 2
				);
			}
			else point.Offset(item.Bounds.Width / 2,
				item.ImageList.ImageSize.Width / 2
			);
			return point; 
		}
		private void OnMouseUpObjectsList(object sender, MouseEventArgs e)
		{
			if (e.Button != MouseButtons.Right) return;

			Point point = new Point(e.X, e.Y);
			contextMenu.Show(objectListView, point);
		}
		private void OnKeyDownObjectsList(object sender, KeyEventArgs e)
		{
			switch (e.KeyData)
			{
			case Keys.F2:
			{
				if (objectListView.SelectedItems.Count == 1) break;
				ConsoleNode node = (ConsoleNode)objectListView.SelectedItems[0].Tag;
				if (node.Node.CanEdit) OnNodeRename(node, sender, e); break;
			}
			case Keys.F10 | Keys.Shift:
			{
				if (objectListView.SelectedItems.Count == 0) break; 
				Point point = GetContextPointObjectsList(objectListView.SelectedItems[0]);
				contextMenu.Show(objectListView, point); e.Handled = true; break; 
			}
			case Keys.Enter:
			{
				if (objectListView.SelectedItems.Count == 1) break;
				ConsoleNode node = (ConsoleNode)objectListView.SelectedItems[0].Tag;
				OnNodeDoubleClick(node, sender, e); break; 
			}
			case Keys.Delete:
			{
				if (objectListView.SelectedItems.Count == 0) break;
                List<ConsoleNode> nodes = new List<ConsoleNode>(); 
                foreach (ListViewItem item in objectListView.SelectedItems)
                { 
                    ConsoleNode node = (ConsoleNode)item.Tag; 
                    if (!node.Node.CanDelete) break; nodes.Add(node); 
                }
				OnNodesDelete(nodes.ToArray(), sender, e); break;
			}
			case Keys.F5:
			{
				RefreshNode(selectedNode); break;
			}
			case Keys.Back:
			{
				if (selectedNode.Parent == null) break;
				objectTreeView.SelectedNode = selectedNode.Parent.TreeNode; break;
			}}
		}
		private void OnKeyUpObjectsList(object sender, KeyEventArgs e)
		{
			if (objectListView.SelectedItems.Count == 0) return; 
			if (e.KeyData != Keys.Apps) return;
			Point point = GetContextPointObjectsList(objectListView.SelectedItems[0]);
			contextMenu.Show(objectListView, point); e.Handled = true;
		}
		private void OnDoubleClickObjectsList(object sender, EventArgs e)
		{
			if (objectListView.SelectedItems.Count == 0) return;
			ConsoleNode node = (ConsoleNode)objectListView.SelectedItems[0].Tag;
			OnNodeDoubleClick(node, sender, e);
		}
		///////////////////////////////////////////////////////////////////////////
		// Логический узел 
		///////////////////////////////////////////////////////////////////////////
		public class Node : IComparable, IComparable<Node>
		{
			// отображаемые иконки
			public virtual string GetIcon(ConsoleNode node) { return "Root.ico"; } 
			// признак нераскрывающихся узлов
			public virtual bool IsLeaf { get { return true; }} 

            // выполнить сравнение элементов
            public virtual int CompareTo(Node node) { return String.Compare(Label, node.Label, true); }
            // выполнить сравнение элементов
            int IComparable.CompareTo(object node) { return CompareTo((Node)node); }

			// перечислить дочерние объекты 
			public virtual Node[] PopulateChilds(ConsoleNode node) { return new Node[0]; }
            // признак сортировки дочерних элементов
            public virtual SortOrder ChildSortOrder { get { return SortOrder.None; } }

            // тип символов в имени
            public virtual CharacterCasing Casing { get { return CharacterCasing.Normal; }}
		    // признак допустимости редактирования 
		    public virtual bool CanEdit { get { return false; } }

		    // получить значение узла
		    public virtual string Label { get { return ToString(); }}
		    // установить значение узла
		    public virtual void SetLabel(ConsoleNode node, string label) {} 

			// признак допустимости удаления 
			public virtual bool CanDelete { get { return false; } }
			// удалить объект
			public virtual void DeleteObject(ConsoleNode node) {}
		    // удалить объекты
			public virtual void DeleteChilds(ConsoleNode node, ConsoleNode[] childs)
            {
			    // для всех объектов
                foreach (ConsoleNode child in childs) 
                {
			        // удалить объект
                    child.Node.DeleteObject(child); node.MainForm.DeleteNode(child); 
                }
            }
			// обработать двойное нажатие
			public virtual void OnProperty(ConsoleNode node, object sender, EventArgs e) {}

			// обработать событие получения справки
			public virtual void OnHelp(ConsoleNode node, object sender, EventArgs e)	{}

			// элементы контекстного меню для узла
			public virtual ToolStripItem[] GetContextMenuItems(ConsoleNode node) 
			{ 
				// элементы контекстного меню для узла
				return new ToolStripItem[0]; 
			}
		}
        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            // запросить подтверждение пользователя
			if (DialogResult.Yes != MessageBox.Show(
				this, Resource.FormEnterExit, Text, MessageBoxButtons.YesNo,
				MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2
			)) 
            // отменить действие
			{ e.Cancel = true; Activate(); } 
        }
	}
}

