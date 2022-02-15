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
	// �������� ���� �������
	///////////////////////////////////////////////////////////////////////////
	public partial class ConsoleForm : Form
	{
        // ������������ ��������-���
   		private ProgressBar progressBar;

		// �������� � ��������� ���������� ����
		private ConsoleNode rootNode; private ConsoleNode selectedNode; 

		// �����������
		public ConsoleForm() { InitializeComponent(); 

			// ���������� ������ ������ ������-����
			applicationStatusBar.Panels[1].AutoSize = StatusBarPanelAutoSize.Spring;  

            // ������� ��������-���
            progressBar = new ProgressBar(); progressBar.BringToFront();

			// ��������������� ��������-��� �� ������-����
			progressBar.Location = new Point(applicationStatusBar.Panels[0].Width + 2, 2); 

            // ���������� ������ ��������-����
			progressBar.Width  = applicationStatusBar.Width  - progressBar.Location.X; 
			progressBar.Height = applicationStatusBar.Height - progressBar.Location.Y; 

			// ���������� ������� ��������-����
			progressBar.Minimum = 0; progressBar.Maximum = 100;

            // ������� ����� ��������-����
            progressBar.Style = ProgressBarStyle.Continuous; progressBar.Visible = false; 

			// ���������� ��������-��� � ������-����
			applicationStatusBar.Controls.Add(progressBar);
		} 
        // ���������� ����� � ������-����
		public void SetText(string text) 
		{ 
			// ��������� ������� ���������
			if (String.IsNullOrEmpty(text)) text = Resource.StatusReady; 

			// ���������� ���������
			mainStatusBarPanel.Text = text; 
		}
		// �������� ����
		public virtual void ChangeLanguage(CultureInfo culture) 
		{
			// �������� �������� ��������
			ComponentResourceManager manager = new ComponentResourceManager(typeof(ConsoleForm));

			// ���������� �������� ��������� ���� �������� ������
			fileMenu  .Text = manager.GetString("fileMenu.Text"  , culture);
			actionMenu.Text = manager.GetString("actionMenu.Text", culture);
			viewMenu  .Text = manager.GetString("viewMenu.Text"  , culture);
			helpMenu  .Text = manager.GetString("helpMenu.Text"  , culture);

			// ���������� �������� ��������� ������� ������
			exitMenuItem      .Text = manager.GetString("exitMenuItem.Text"      , culture);
			largeIconsMenuItem.Text = manager.GetString("largeIconsMenuItem.Text", culture);
			smallIconsMenuItem.Text = manager.GetString("smallIconsMenuItem.Text", culture);
			listMenuItem	  .Text = manager.GetString("listMenuItem.Text"      , culture);
			aboutMenuItem	  .Text = manager.GetString("aboutMenuItem.Text"     , culture);

			// �������������� ��������� �� ���������� ���������
			objectListView.EmptyMessage = Resource.EmptyListView;

			// �������� ���������� ������ ���������
			if (objectListView.Items.Count == 0) objectListView.Refresh(); 

			// �������� ������ ������-����
			mainStatusBarPanel.Text = Resource.StatusReady; 
		}
		// �������� � ��������� ���������� ����
		public ConsoleNode RootNode     { get { return rootNode;     }}
		public ConsoleNode SelectedNode { get { return selectedNode; }}

        // ���� ����������� ��������        
		public TreeView TreeView { get { return objectTreeView; }}

        // ���� ����������� ��������        
		public ListView ListView { get { return objectListView; }}

        // ��������-���
        public ProgressBar ProgressBar { get { return progressBar; }}

		///////////////////////////////////////////////////////////////////////
		// ���������������� �������
		///////////////////////////////////////////////////////////////////////
		protected virtual Icon GetIcon(string name) 
		{ 
			// ���������� ����������� ������
			Assembly assembly = Assembly.GetExecutingAssembly();

			// ���������� ��� �������
			string resource = assembly.GetName().Name + "." + name;

			// ������� ��������� ������
			return new Icon(assembly.GetManifestResourceStream(resource)); 
		} 
		// �������� ����
		protected virtual Node GetRootNode() { return new Node(); } 

		// ��� �����
		protected virtual String GetName() { return String.Empty; } 

		// ���������� ���� Help
		protected virtual ToolStripItem[] GetHelpItems() 
		{ 
			// ���������� ���� Help
			return new ToolStripItem[0]; 
		}  
		///////////////////////////////////////////////////////////////////////
		// ������������� ��������� ����
		///////////////////////////////////////////////////////////////////////
		protected virtual void OnLoad(object sender, EventArgs e)
		{
			// �������� ���������� ���� Help
			ToolStripItem[] helpItems = GetHelpItems(); Array.Resize(ref helpItems, helpItems.Length + 1); 

			// ��������� ���� About
			helpItems[helpItems.Length - 1] = helpMenu.DropDownItems[0]; 

			// �������������� ���� Help
			helpMenu.DropDownItems.Clear(); helpMenu.DropDownItems.AddRange(helpItems); 

			// ������� �������� ����
            rootNode = new ConsoleNode(this, GetRootNode()); selectedNode = null; 

            // ���������� ��������� �����
			objectListView.EmptyMessage = Resource.EmptyListView; Text = GetName(); 

			// ������� �������� ����
            Activate(); objectTreeView.AfterSelect -= OnAfterSelectObjectsTree;

			// ���������� ���� � ����������� ����������
			objectTreeView.Nodes.Clear(); objectTreeView.Nodes.Add(rootNode.TreeNode);

			// �������� ����
			objectTreeView.SelectedNode = rootNode.TreeNode; selectedNode = rootNode;

			// ���������� ���������� �������
            objectTreeView.AfterSelect += OnAfterSelectObjectsTree; 
 
			// ����������� �������� ����
            RefreshNode(rootNode); rootNode.TreeNode.Expand();

            // ���������� ������ ������
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 
        }
		protected virtual void OnResize(object sender, EventArgs e)
		{
			// ���������� ������� ������-����
			applicationStatusBar.SizingGrip = (FormWindowState.Maximized != WindowState);

			// ��������������� ��������-��� �� ������-����
			progressBar.Location = new Point(applicationStatusBar.Panels[0].Width + 2, 2); 

            // ���������� ������ ��������-����
			progressBar.Width  = applicationStatusBar.Width  - progressBar.Location.X; 
			progressBar.Height = applicationStatusBar.Height - progressBar.Location.Y; 

            // ���������� ������ ������
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 
		}
		///////////////////////////////////////////////////////////////////////
		// ����������� ������������� �������
		///////////////////////////////////////////////////////////////////////
		private void OnAbout(object sender, EventArgs e)
		{
			// ���������� ����� ������ ����������
			string version = Application.ProductVersion; 

			// ������������ ���������� � ����������
			string message = String.Format("{0}. {1} {2}.\r\n{3}",
				Text, Resource.CommonVersion, version, Resource.CommonCopyright
			);
			// ������� ���������� � ����������
			MessageBox.Show(this, message, Resource.CommonAbout);
		}
		private void OnClickExitMenu(object sender, EventArgs e)
		{
			Close(); // ������� ����
		}
		private void OnClickLargeIconsMenu(object sender, EventArgs e)
		{
			// �������������� ��������� ������ �����������
			objectListView.View = View.LargeIcon;

            // ���������� ������ ������
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 

			// ���������� ��������� ����� ����
			largeIconsMenuItem.Checked = true;
			smallIconsMenuItem.Checked = false; 
			listMenuItem      .Checked = false; 
		}
		private void OnClickSmallIconsMenu(object sender, EventArgs e)
		{
			// �������������� ��������� ������ �����������
			objectListView.View = View.SmallIcon;

            // ���������� ������ ������
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 

			// �������������� ��������� ������ �����������
			largeIconsMenuItem.Checked = false;
			smallIconsMenuItem.Checked = true; 
			listMenuItem      .Checked = false; 
		}
		private void OnClickListMenu(object sender, EventArgs e)
		{
			// �������������� ��������� ������ �����������
			objectListView.View = View.List;

            // ���������� ������ ������
            int width = objectListView.ClientSize.Width; 
            objectListView.Columns[0].Width = -1;
            if (objectListView.Columns[0].Width < width) 
                objectListView.Columns[0].Width = width; 

			// �������������� ��������� ������ �����������
			largeIconsMenuItem.Checked = false;
			smallIconsMenuItem.Checked = false; 
			listMenuItem      .Checked = true; 
		}
        ///////////////////////////////////////////////////////////////////////
        // ����������� ������� �����
        ///////////////////////////////////////////////////////////////////////
		internal void SelectNode(ConsoleNode node)
		{
			// �������� ������� 
			if (!node.Node.IsLeaf) objectTreeView.SelectedNode = node.TreeNode; 
		}
		internal ConsoleNode[] RefreshNode(ConsoleNode node)
		{
			List<ConsoleNode> childNodes = new List<ConsoleNode>(); 

			// �������� ������ � �����
			InvalidateNode(node); if (node.Node.IsLeaf) return childNodes.ToArray(); 

            // ������� ������ ���� ���������� ���������
            List<String> listSelectedLabels = new List<String>(); 

            // ��� ���� ���������� �����
            foreach (ListViewItem listViewItem in objectListView.SelectedItems)
            {
                // �������� ���������� �������
                ConsoleNode consoleNode = (ConsoleNode)listViewItem.Tag; 

                // ��������� ��� ����������� ����
                listSelectedLabels.Add(consoleNode.Node.Label); 
            }
			// ������ ���������� ����������������� ����������
			objectTreeView.BeginUpdate(); objectListView.BeginUpdate();

			// �������� ����� �������
			Cursor cursor  = Cursor.Current; Cursor.Current = Cursors.WaitCursor;
			try {
				// �������� ������ �������� ���������
				node.TreeNode.Nodes.Clear(); 

				// �������� ������ ������������ ���������
				if (selectedNode == node) objectListView.Items.Clear();

				// �������� �������� ��������
				Node[] childs = node.Node.PopulateChilds(node); 

                // ��������� ����������
                if (node.Node.ChildSortOrder == SortOrder.Ascending ) Array.Sort   (childs);
                if (node.Node.ChildSortOrder == SortOrder.Descending) Array.Reverse(childs); 
                
				// ��� ������� ��������� ��������
				foreach (Node child in childs)
				{
					// �������� �������� ������
					ConsoleNode childNode = new ConsoleNode(node, child);

					// �������� ���� � ������������� ������
					if (!child.IsLeaf) node.TreeNode.Nodes.Add(childNode.TreeNode);

					// �������� ������� � ������ ���������
					if (selectedNode == node) objectListView.Items.Add(childNode.ListNode);

					// �������� ������ � ����� ��� ������ ����
					InvalidateNode(childNode); childNodes.Add(childNode); 

                    // ��� ����� ����������� ��������
                    if (listSelectedLabels.Contains(child.Label))
                    {
                        // �������� ����� ���������� �������
                        childNode.ListNode.Focused  = true; 
                        childNode.ListNode.Selected = true; 
                    }
				}
				return childNodes.ToArray(); 
			}
			// ��� ������ 
			catch (Exception ex) 
            {
                // ������� �������� ������
				ErrorDialog.Show(this, ex); return childNodes.ToArray(); 
            }
			// ������������ ����� �������
			finally { Cursor.Current = cursor; 
			
				// ��������� ���������� ����������������� ����������
				objectListView.EndUpdate(); objectTreeView.EndUpdate();
			}
		}
		private void InvalidateNode(ConsoleNode node)
		{
			// �������� ������ ������ ������������ ����������
			ImageList smallImagesTree = objectTreeView.ImageList;
			ImageList smallImagesList = objectListView.SmallImageList;
			ImageList largeImagesList = objectListView.LargeImageList;

            // �������� ��� ������
            string iconName = node.Node.GetIcon(node); 

			// ��� ���������� ������ � ������
			if (!smallImagesTree.Images.ContainsKey(iconName))
			{
				// �������� ��������� ������
				Icon smallIcon = new Icon(GetIcon(iconName), 16, 16);

				// �������� ������ � ������
				smallImagesTree.Images.Add(iconName, smallIcon.ToBitmap());
			}
			// ��� ���������� ������ � ������
			if (!smallImagesList.Images.ContainsKey(iconName))
			{
				// �������� ��������� ������
				Icon smallIcon = new Icon(GetIcon(iconName), 16, 16);

				// �������� ������ � ������
				smallImagesList.Images.Add(iconName, smallIcon.ToBitmap());
			}
			// ��� ���������� ������ � ������
			if (!largeImagesList.Images.ContainsKey(iconName))
			{
				// �������� ��������� ������
				Icon largeIcon = new Icon(GetIcon(iconName), 32, 32);

				// �������� ������ � ������
				largeImagesList.Images.Add(iconName, largeIcon.ToBitmap());
			}
			// ���������� ������ ��� ��������
			node.TreeNode.SelectedImageKey = iconName;

			// ���������� ������ ��� ��������
			node.TreeNode.ImageKey = iconName; node.ListNode.ImageKey = iconName;

			// ���������� ����� ��� ��������
			node.TreeNode.Text = node.Node.Label; node.ListNode.Text = node.Node.Label;
		}
		private void DeleteNode(ConsoleNode node)
		{
            // ������� ���� �� �������������� ������
            if (!node.Node.IsLeaf) node.TreeNode.Remove();

            // ��� ���������� ������������ ����
            if (selectedNode == node.Parent)
            {
                // ������� ������� �� ������ ���������
	            objectListView.Items.Remove(node.ListNode);
            }
        }
		private void OnNodeDoubleClick(ConsoleNode node, object sender, EventArgs e)
		{
			// ������� ���������� �������
			if (node.Node.IsLeaf) node.Node.OnProperty(node, sender, e); 
			else {
				// ���������� ��� �������� �������� ��������
				if (node.TreeNode.IsExpanded) node.TreeNode.Collapse(); else node.TreeNode.Expand();

				// �������� ������� � ������������� ������
				objectTreeView.SelectedNode = node.TreeNode; 
			}
		}
		private void OnNodeRename(ConsoleNode node, object sender, EventArgs e)
		{
			// ���������� ���������� ���������� ��������������
			objectListView.AfterLabelEdit += OnNodeRenameEnd;

			// ��������� ����� ��������� �����
			if (objectListView.SelectedItems.Count != 1) return;

			// ������ ��������������
			objectListView.LabelEdit = true; objectListView.SelectedItems[0].BeginEdit();
		}
		private void OnNodeRenameEnd(object sender, LabelEditEventArgs e)
		{
			// �������� ���������� ���������� ��������������
			objectListView.AfterLabelEdit -= OnNodeRenameEnd; objectListView.LabelEdit = false;

			// ���������� ���� ��������������
			ConsoleNode node = (ConsoleNode)objectListView.Items[e.Item].Tag;

			// ��������� ��������� ������
			if (e.Label == null || node.Node.Label == e.Label) return; string label = e.Label; 
            
            // �������� ������� ��������
            if (node.Node.Casing == CharacterCasing.Lower) label = label.ToLower(); 
            if (node.Node.Casing == CharacterCasing.Upper) label = label.ToUpper(); 

			// �������� ������������ ��� ��������
			try { node.Node.SetLabel(node, label); node.ListNode.Text = label; e.CancelEdit = false; }

			// ��� ������ ������� �� ��������
			catch (Exception ex) { e.CancelEdit = true; Aladdin.GUI.ErrorDialog.Show(this, ex); }
		}
		private void OnNodesDelete(ConsoleNode[] nodes, object sender, EventArgs e)
		{
		    // ������� �������
    		try { nodes[0].Parent.Node.DeleteChilds(nodes[0].Parent, nodes); }

			// ��� ������ ������� �� ��������
			catch (Exception ex) { ErrorDialog.Show(this, ex); }
		}
		private void OnNodeHelp(ConsoleNode node, object sender, EventArgs e)
		{
			// ���������� �������
			node.Node.OnHelp(node, sender, e);
		}
		///////////////////////////////////////////////////////////////////////
		// ���������� ������������ � ����������� �� ���������
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
		// ����������� ������� �������������� ������ �����
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
		// ����������� ������� ������ �����
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
		// ���������� ���� 
		///////////////////////////////////////////////////////////////////////////
		public class Node : IComparable, IComparable<Node>
		{
			// ������������ ������
			public virtual string GetIcon(ConsoleNode node) { return "Root.ico"; } 
			// ������� ���������������� �����
			public virtual bool IsLeaf { get { return true; }} 

            // ��������� ��������� ���������
            public virtual int CompareTo(Node node) { return String.Compare(Label, node.Label, true); }
            // ��������� ��������� ���������
            int IComparable.CompareTo(object node) { return CompareTo((Node)node); }

			// ����������� �������� ������� 
			public virtual Node[] PopulateChilds(ConsoleNode node) { return new Node[0]; }
            // ������� ���������� �������� ���������
            public virtual SortOrder ChildSortOrder { get { return SortOrder.None; } }

            // ��� �������� � �����
            public virtual CharacterCasing Casing { get { return CharacterCasing.Normal; }}
		    // ������� ������������ �������������� 
		    public virtual bool CanEdit { get { return false; } }

		    // �������� �������� ����
		    public virtual string Label { get { return ToString(); }}
		    // ���������� �������� ����
		    public virtual void SetLabel(ConsoleNode node, string label) {} 

			// ������� ������������ �������� 
			public virtual bool CanDelete { get { return false; } }
			// ������� ������
			public virtual void DeleteObject(ConsoleNode node) {}
		    // ������� �������
			public virtual void DeleteChilds(ConsoleNode node, ConsoleNode[] childs)
            {
			    // ��� ���� ��������
                foreach (ConsoleNode child in childs) 
                {
			        // ������� ������
                    child.Node.DeleteObject(child); node.MainForm.DeleteNode(child); 
                }
            }
			// ���������� ������� �������
			public virtual void OnProperty(ConsoleNode node, object sender, EventArgs e) {}

			// ���������� ������� ��������� �������
			public virtual void OnHelp(ConsoleNode node, object sender, EventArgs e)	{}

			// �������� ������������ ���� ��� ����
			public virtual ToolStripItem[] GetContextMenuItems(ConsoleNode node) 
			{ 
				// �������� ������������ ���� ��� ����
				return new ToolStripItem[0]; 
			}
		}
        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            // ��������� ������������� ������������
			if (DialogResult.Yes != MessageBox.Show(
				this, Resource.FormEnterExit, Text, MessageBoxButtons.YesNo,
				MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2
			)) 
            // �������� ��������
			{ e.Cancel = true; Activate(); } 
        }
	}
}

