using System.Windows.Forms;

namespace Aladdin.GUI
{
	public partial class ConsoleForm : Form
	{
		private System.ComponentModel.IContainer components;

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (components != null)
				{
					components.Dispose();
				}
			}
			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ConsoleForm));
            this.applicationMainMenu = new System.Windows.Forms.MenuStrip();
            this.fileMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.exitMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.actionMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.viewMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.largeIconsMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.smallIconsMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.listMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.helpMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.applicationStatusBar = new System.Windows.Forms.StatusBar();
            this.mainStatusBarPanel = new System.Windows.Forms.StatusBarPanel();
            this.paramStatusBarPanel = new System.Windows.Forms.StatusBarPanel();
            this.contextMenu = new System.Windows.Forms.ContextMenuStrip();
            this.smallImageList = new System.Windows.Forms.ImageList(this.components);
            this.objectTreeView = new System.Windows.Forms.TreeView();
            this.splitter = new System.Windows.Forms.Splitter();
            this.largeImageList = new System.Windows.Forms.ImageList(this.components);
            this.nameColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.objectListView = new Aladdin.GUI.ListView();
            this.columnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            ((System.ComponentModel.ISupportInitialize)(this.mainStatusBarPanel)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.paramStatusBarPanel)).BeginInit();
            this.SuspendLayout();
            // 
            // applicationMainMenu
            // 
            this.applicationMainMenu.Items.AddRange(new System.Windows.Forms.ToolStripMenuItem[] {
            this.fileMenu,
            this.actionMenu,
            this.viewMenu,
            this.helpMenu});
            // 
            // fileMenu
            // 
            this.fileMenu.DropDownItems.AddRange(new System.Windows.Forms.ToolStripMenuItem[] {
            this.exitMenuItem});
            resources.ApplyResources(this.fileMenu, "fileMenu");
            // 
            // exitMenuItem
            // 
            resources.ApplyResources(this.exitMenuItem, "exitMenuItem");
            this.exitMenuItem.Click += new System.EventHandler(this.OnClickExitMenu);
            // 
            // actionMenu
            // 
            resources.ApplyResources(this.actionMenu, "actionMenu");
            this.actionMenu.DropDownOpening += new System.EventHandler(this.OnPopupActionMenu);
            // 
            // viewMenu
            // 
            this.viewMenu.DropDownItems.AddRange(new System.Windows.Forms.ToolStripMenuItem[] {
            this.largeIconsMenuItem,
            this.smallIconsMenuItem,
            this.listMenuItem});
            resources.ApplyResources(this.viewMenu, "viewMenu");
            // 
            // largeIconsMenuItem
            // 
            resources.ApplyResources(this.largeIconsMenuItem, "largeIconsMenuItem");
            this.largeIconsMenuItem.Click += new System.EventHandler(this.OnClickLargeIconsMenu);
            // 
            // smallIconsMenuItem
            // 
            resources.ApplyResources(this.smallIconsMenuItem, "smallIconsMenuItem");
            this.smallIconsMenuItem.Click += new System.EventHandler(this.OnClickSmallIconsMenu);
            // 
            // listMenuItem
            // 
            this.listMenuItem.Checked = true;
            resources.ApplyResources(this.listMenuItem, "listMenuItem");
            this.listMenuItem.Click += new System.EventHandler(this.OnClickListMenu);
            // 
            // helpMenu
            // 
            this.helpMenu.DropDownItems.AddRange(new System.Windows.Forms.ToolStripMenuItem[] {
            this.aboutMenuItem});
            resources.ApplyResources(this.helpMenu, "helpMenu");
            // 
            // aboutMenuItem
            // 
            resources.ApplyResources(this.aboutMenuItem, "aboutMenuItem");
            this.aboutMenuItem.Click += new System.EventHandler(this.OnAbout);
            // 
            // applicationStatusBar
            // 
            resources.ApplyResources(this.applicationStatusBar, "applicationStatusBar");
            this.applicationStatusBar.Name = "applicationStatusBar";
            this.applicationStatusBar.Panels.AddRange(new System.Windows.Forms.StatusBarPanel[] {
            this.mainStatusBarPanel,
            this.paramStatusBarPanel});
            this.applicationStatusBar.ShowPanels = true;
            // 
            // mainStatusBarPanel
            // 
            resources.ApplyResources(this.mainStatusBarPanel, "mainStatusBarPanel");
            // 
            // paramStatusBarPanel
            // 
            resources.ApplyResources(this.paramStatusBarPanel, "paramStatusBarPanel");
            // 
            // contextMenu
            // 
            this.contextMenu.Opening += new System.ComponentModel.CancelEventHandler(this.OnPopupContextMenu);
            // 
            // smallImageList
            // 
            this.smallImageList.ColorDepth = System.Windows.Forms.ColorDepth.Depth8Bit;
            resources.ApplyResources(this.smallImageList, "smallImageList");
            this.smallImageList.TransparentColor = System.Drawing.Color.Transparent;
            // 
            // objectTreeView
            // 
            this.objectTreeView.CausesValidation = false;
            resources.ApplyResources(this.objectTreeView, "objectTreeView");
            this.objectTreeView.HideSelection = false;
            this.objectTreeView.ImageList = this.smallImageList;
            this.objectTreeView.ItemHeight = 16;
            this.objectTreeView.Name = "objectTreeView";
            this.objectTreeView.ShowRootLines = false;
            this.objectTreeView.KeyDown += new System.Windows.Forms.KeyEventHandler(this.OnKeyDownObjectsTree);
            this.objectTreeView.KeyUp += new System.Windows.Forms.KeyEventHandler(this.OnKeyUpObjectsTree);
            this.objectTreeView.MouseUp += new System.Windows.Forms.MouseEventHandler(this.OnMouseUpObjectsTree);
            // 
            // splitter
            // 
            resources.ApplyResources(this.splitter, "splitter");
            this.splitter.Name = "splitter";
            this.splitter.TabStop = false;
            // 
            // largeImageList
            // 
            this.largeImageList.ColorDepth = System.Windows.Forms.ColorDepth.Depth8Bit;
            resources.ApplyResources(this.largeImageList, "largeImageList");
            this.largeImageList.TransparentColor = System.Drawing.Color.Transparent;
            // 
            // nameColumnHeader
            // 
            resources.ApplyResources(this.nameColumnHeader, "nameColumnHeader");
            // 
            // objectListView
            // 
            this.objectListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader});
            resources.ApplyResources(this.objectListView, "objectListView");
            this.objectListView.EmptyMessage = "";
            this.objectListView.FullRowSelect = true;
            this.objectListView.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.None;
            this.objectListView.HideSelection = false;
            this.objectListView.LabelTip = false;
            this.objectListView.LargeImageList = this.largeImageList;
            this.objectListView.Name = "objectListView";
            this.objectListView.SmallImageList = this.smallImageList;
            this.objectListView.UseCompatibleStateImageBehavior = false;
            this.objectListView.View = System.Windows.Forms.View.List;
            this.objectListView.DoubleClick += new System.EventHandler(this.OnDoubleClickObjectsList);
            this.objectListView.KeyDown += new System.Windows.Forms.KeyEventHandler(this.OnKeyDownObjectsList);
            this.objectListView.KeyUp += new System.Windows.Forms.KeyEventHandler(this.OnKeyUpObjectsList);
            this.objectListView.MouseUp += new System.Windows.Forms.MouseEventHandler(this.OnMouseUpObjectsList);
            // 
            // columnHeader
            // 
            resources.ApplyResources(this.columnHeader, "columnHeader");
            // 
            // ConsoleForm
            // 
            resources.ApplyResources(this, "$this");
            this.Controls.Add(this.objectListView);
            this.Controls.Add(this.splitter);
            this.Controls.Add(this.objectTreeView);
            this.Controls.Add(this.applicationMainMenu);
            this.Controls.Add(this.applicationStatusBar);
            this.MainMenuStrip = this.applicationMainMenu;
            this.Name = "ConsoleForm";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.OnFormClosing);
            this.Load += new System.EventHandler(this.OnLoad);
            this.Resize += new System.EventHandler(this.OnResize);
            ((System.ComponentModel.ISupportInitialize)(this.mainStatusBarPanel)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.paramStatusBarPanel)).EndInit();
            this.ResumeLayout(false);

		}
		#endregion

		private System.Windows.Forms.ContextMenuStrip contextMenu;
		private System.Windows.Forms.Splitter splitter;
		private System.Windows.Forms.MenuStrip applicationMainMenu;
		private System.Windows.Forms.ToolStripMenuItem fileMenu;
		private System.Windows.Forms.ToolStripMenuItem exitMenuItem;
		private System.Windows.Forms.ToolStripMenuItem actionMenu;
		private System.Windows.Forms.ToolStripMenuItem largeIconsMenuItem;
		private System.Windows.Forms.ToolStripMenuItem smallIconsMenuItem;
		private System.Windows.Forms.ToolStripMenuItem listMenuItem;
		private System.Windows.Forms.ToolStripMenuItem helpMenu;
		private System.Windows.Forms.ToolStripMenuItem viewMenu;
		private System.Windows.Forms.ToolStripMenuItem aboutMenuItem;
		private System.Windows.Forms.ImageList smallImageList;
		private System.Windows.Forms.ImageList largeImageList;
		private System.Windows.Forms.StatusBar applicationStatusBar;
		private System.Windows.Forms.StatusBarPanel mainStatusBarPanel;
		private System.Windows.Forms.StatusBarPanel paramStatusBarPanel;
		private System.Windows.Forms.ColumnHeader nameColumnHeader;
		private System.Windows.Forms.TreeView objectTreeView;
		private Aladdin.GUI.ListView objectListView;
        private ColumnHeader columnHeader;
	}
}
