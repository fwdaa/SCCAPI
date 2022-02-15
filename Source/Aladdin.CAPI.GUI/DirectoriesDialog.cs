using System;
using System.Windows.Forms;
using System.Collections.Generic;
using Aladdin.GUI; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Окно отображения контейнеров
	///////////////////////////////////////////////////////////////////////////
	public partial class DirectoriesDialog : Form
	{
		// родительское окно и набор каталогов
		private ContainersForm owner; private Software.DirectoriesStore store; 

        // списки добавленных и удаленных каталогов
        private List<String> toBeAdded; private List<String> toBeRemoved;

        // конструктор
		public DirectoriesDialog() { InitializeComponent(); }

        // конструктор
		public DirectoriesDialog(ContainersForm owner, Software.DirectoriesStore store)
		{ 
			// инициализировать дочерние элементы
			InitializeComponent(); buttonRemove.Enabled = false; 

			// сохранить переданные параметры
			this.owner = owner; this.store = store;  

            // создать пустые списки
            toBeAdded = new List<String>(); toBeRemoved = new List<String>();

            // для всех каталогов
            foreach (string directory in store.EnumerateObjects())
            { 
			    // указать информацию о новом элементе в список
			    ListViewItem item = new ListViewItem(new string[] { directory });

                // добавить созданную информацию
			    item.ToolTipText = directory; listView.Items.Add(item);
            }
		}

        private void OnSelectedIndexChanged(object sender, EventArgs e)
        {
            // указать доступность кнопки
            buttonRemove.Enabled = listView.SelectedItems.Count > 0; 
        }
        private void OnClickAdd(object sender, EventArgs e)
        {
			// выбрать каталог контейнеров
            string directory = owner.SelectDirectory(this); 

			// проверить выбор диалога
            if (directory == null) return; 

            // для всех элементов списка
            foreach (ListViewItem item in listView.Items)
            {
                // проверить присутствие каталога
                if (item.Text.ToLower() == directory) return; 
            }
            // удалить каталог из удаленных
            if (toBeRemoved.Contains(directory)) toBeRemoved.Remove(directory); 

            // добавить каталог в список новых каталогов
            else toBeAdded.Add(directory);
            { 
		        // указать информацию о новом элементе в список
		        ListViewItem item = new ListViewItem(new string[] { directory });

                // добавить созданную информацию
                item.ToolTipText = directory; listView.Items.Add(item);
            }
        }
        private void OnClickRemove(object sender, EventArgs e)
        {
            // для всех выбранных элементов
            foreach (ListViewItem item in listView.SelectedItems)
            {
                // извлечь имя каталога
                string directory = item.Text; 

                // удалить каталог из добавленных
                if (toBeAdded.Contains(directory)) toBeAdded.Remove(directory); 

                // добавить каталог в удаленные
                else toBeRemoved.Add(directory); 
            }
            // удалить выбранные элементы из списка
            foreach (ListViewItem item in listView.SelectedItems) item.Remove(); 
        }
        private void OnClickOK(object sender, EventArgs e)
        {
            // проверить необходимость действий
            if (toBeAdded.Count == 0 && toBeRemoved.Count == 0) return; 

			// изменить состояние курсора
			Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor; 
			try { 
                // запретить закрытие диалога
                DialogResult = DialogResult.None; 

                // для всех удаляемых каталогов
                foreach (string directory in toBeRemoved) 
                {
                    // удалить каталог
                    store.DeleteObject(directory, null); 
                }
                // для всех добавляемых каталогов
                foreach (string directory in toBeAdded)
                {
                    // добавить каталог
                    using (SecurityObject obj = store.CreateObject(null, directory, null)) {}
                }
				// получить сообщение
				string message = Resource.StatusChangeDirectories; 

				// вывести сообщение
				MessageBox.Show(this, message, Text, 
                    MessageBoxButtons.OK, MessageBoxIcon.Information
                );  
                // указать закрытие диалога
                DialogResult = DialogResult.OK; 
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(this, ex); }

			// восстановить состояние курсора
			finally { Cursor.Current = cursor; }
        }
	}
}
