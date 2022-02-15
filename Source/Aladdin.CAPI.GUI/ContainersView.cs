using System;
using System.IO;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	//////////////////////////////////////////////////////////////////////////////
	// Закладка диалога контейнеров
	//////////////////////////////////////////////////////////////////////////////
	public partial class ContainersView : UserControl
	{
		private ContainersDialog  parent;            // родительский диалог
		private CryptoProvider    provider;		     // криптографический провайдер
		private OpenFileDialog	  certificateDialog; // диалог выбора сертификата
		private SaveFileDialog	  requestDialog;	 // диалог выбора запроса
		
		public ContainersView(ContainersDialog parent, CryptoProvider provider, 
            OpenFileDialog certificateDialog, SaveFileDialog requestDialog) 
		{
			// выполнить инициализацию
			InitializeComponent(); this.parent = parent; this.provider = provider;
			
			// сохранить переданные параметры
			this.certificateDialog = certificateDialog; this.requestDialog = requestDialog; 

			// создать элементы контекстного меню
			ToolStripItem itemShow = new ToolStripMenuItem(Resource.MenuShowContainer, null, OnDoubleClick); 

			// указать контекстное меню
			listView.ContextMenuStrip = new ContextMenuStrip(); 
			listView.ContextMenuStrip.Items.AddRange(new ToolStripItem[] { itemShow }); 
		}
		public ContainersView() { InitializeComponent(); }

		// обновить список контейнеров
		public new void Refresh()  
		{ 
			// очистить список контейнеров
			Scope scope = parent.Scope; listView.Items.Clear();
		 
			// сделать контекстное меню доступным/недоступным
			OnSelectedIndexChanged(this, EventArgs.Empty);

            // перечислить контейнеры
			foreach (SecurityInfo info in provider.EnumerateAllObjects(scope))
			{
                // определить полное имя
                string fullName = info.FullName; 

				// указать информацию о новом элементе в список
				ListViewItem item = new ListViewItem(new string[] { fullName });

				// добавить новый элемент в список
				item.ToolTipText = fullName; item.Tag = info; listView.Items.Add(item); 
			}
		}
		private void OnSelectedIndexChanged(object sender, EventArgs e)
		{
			// определить допустимость действий
			bool selected = listView.SelectedItems.Count != 0; 

			// сделать контекстное меню доступным/недоступным
			listView.ContextMenuStrip.Items[0].Enabled = selected; 

			// оповестить родительский диалог
			if (!selected) parent.OnSelectContainer(null);
            else { 
                // выполнить преобразование типа
                SecurityInfo info = (SecurityInfo)listView.SelectedItems[0].Tag; 

			    // оповестить родительский диалог
			    parent.OnSelectContainer(info); 
            }
		}
		private void OnDoubleClick(object sender, EventArgs e)
		{
			// получить выделенный элемент
			SecurityInfo info = (SecurityInfo)listView.SelectedItems[0].Tag; 

			// создать диалог контейнера
			ContainerDialog dialog = new ContainerDialog(
                parent.Environment, provider, info, certificateDialog, requestDialog
			); 
			// отобразить диалог выбора контейнера
			if (dialog.ShowDialog(parent) != DialogResult.OK) return; 
			
			// оповестить родительский диалог
			parent.OnSelectContainer(info);
		}
	}
}
