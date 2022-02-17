using System;
using System.Threading;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Security.Permissions;
using Aladdin.GUI; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Окно отображения контейнеров
	///////////////////////////////////////////////////////////////////////////
	public partial class ContainersDialog : Form, PCSC.IReaderHandler
	{
		// функция проверки допустимости контейнера
		public delegate Object Callback(Form form, SecurityInfo info); 

		private OpenFileDialog		         certificateDialog;	// диалог выбора сертификата
		private SaveFileDialog		         requestDialog;		// диалог выбора запроса
		private Remoting.RemoteClientControl listener;		    // поток прослушивания
		private Callback		             callback;		    // функция проверки допустимости

        // выбранный элемент и значение функции обратного вызова
		private SecurityInfo info; private object result;

		// отобразить диалог
		public static object Show(IWin32Window parent, 
            CryptoEnvironment environment, Callback callback)
		{
			// указать начальный каталог
			string selectedPath = System.Environment.GetFolderPath(
				System.Environment.SpecialFolder.Personal
			); 
			// создать диалог выбора файла
			OpenFileDialog certificateDialog = new OpenFileDialog(); 
			certificateDialog.CheckFileExists = true; 
			
			// указать начальный каталог
			certificateDialog.InitialDirectory = selectedPath;

			// установить параметры диалога выбора файла
			certificateDialog.Title  = Resource.TitleOpenCertificateFile;
			certificateDialog.Filter = Resource.FilterCertificateFile;

			// создать диалог выбора файла
			SaveFileDialog requestDialog = new SaveFileDialog(); 
			requestDialog.OverwritePrompt = true; 
			
			// указать начальный каталог
			requestDialog.InitialDirectory = selectedPath;

			// установить параметры диалога выбора файла
			requestDialog.Title  = Resource.TitleSaveRequestFile;
			requestDialog.Filter = Resource.FilterRequestFile;

			// создать диалог выбора контейнера
			ContainersDialog dialog = new ContainersDialog(
				environment, callback, certificateDialog, requestDialog
			); 
			// отобразить диалог
			DialogResult result = ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (result == DialogResult.OK) return dialog.Result;

			// при ошибке выбросить исключение
			throw new OperationCanceledException();
		}
		internal ContainersDialog(CryptoEnvironment environment, 
			Callback callback, OpenFileDialog certificateDialog, SaveFileDialog requestDialog) 
		{ 
			// сохранить переданные параметры
			InitializeComponent(); this.callback = callback;

			// сохранить переданные параметры
			this.certificateDialog = certificateDialog; this.requestDialog = requestDialog;

			// для всех поддерживаемых провайдеров
			foreach (CryptoProvider provider in environment.Providers)
			{
				// добавить страницу закладок
				tabControl.TabPages.Add(CreateTabPage(tabTemplate, environment, provider));
 			}
			// удалить фиктивную страницу
			tabControl.TabPages.Remove(tabTemplate); Refresh(); listener = null; 
			try {  
				// создать прокси для обработчика
				PCSC.IReaderHandler handler = Proxy.Windows.WndClientProxy.Create(
					this, Handle, 0x8000
				); 
				// создать поток прослушивания считывателей
				listener = PCSC.Windows.Provider.Instance.StartListener(handler, null); 
			}
			// обработать ошибку
			catch (Exception ex) { ErrorDialog.Show("PCSC", ex); }
		}
		public ContainersDialog() { InitializeComponent(); }

		protected override void OnClosed(EventArgs e)
		{
			// завершить поток прослушивания считывателей
			base.OnClosed(e); if (listener != null) listener.Dispose();  
		}
		private TabPage CreateTabPage(TabPage template, 
			CryptoEnvironment environment, CryptoProvider provider)
		{
			// создать страницу для провайдера
			ContainersView containersView = new ContainersView(
				this, environment, provider, certificateDialog, requestDialog
			); 
			// указать провайдер для страницы
			TabPage tabPage = new TabPage(); tabPage.Location = template.Location; 

			// указать параметры визуальной страницы
			tabPage.Padding = template.Padding; tabPage.Size = template.Size;	 

			// связать страницу с представлением 
			tabPage.Text = provider.Name; tabPage.Controls.Add(containersView); return tabPage; 
		}
		// вернуть область видимости
		public Scope Scope { get { return checkSystem.Checked ? Scope.System : Scope.Any; }}

		private void OnScopeChanged(object sender, EventArgs e) 
        { 
            // обновить элементы управления
            OnTabControlChanged(this, EventArgs.Empty); 
        } 
		///////////////////////////////////////////////////////////////////////
		// Обработка событий смарт-карт
		///////////////////////////////////////////////////////////////////////
        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        protected override void WndProc(ref Message message)
        {
	        // вызвать базовую функцию
	        base.WndProc(ref message); if (message.Msg != 0x8000) return;

            // обработать сообщение
            Proxy.Windows.WndClientProxy.WndProc(ref message); 
        }
	    // добавление/удаление считывателя
	    public virtual void OnInsertReader(PCSC.Reader reader) {}
	    public virtual void OnRemoveReader(PCSC.Reader reader) {}

	    // добавление смарт-карты
	    public virtual void OnInsertCard(PCSC.Reader reader) 
        {
            // проверить наличие активной закладки
            if (tabControl.SelectedIndex < 0) return; 

			// установить форму курсора
			Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor;
            try {  
			    // обновить содержимое
			    Thread.Sleep(5000); OnTabControlChanged(this, EventArgs.Empty); 
            }
            // восстановить форму курсора
            finally { Cursor.Current = cursor; }
        }
	    // удаление смарт-карты
	    public virtual void OnRemoveCard(PCSC.Reader reader) 
        {
            // проверить наличие активной закладки
            if (tabControl.SelectedIndex < 0) return; 

		    // установить форму курсора
		    Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor;
            try { 
		        // обновить содержимое
		        Thread.Sleep(5000); OnTabControlChanged(this, EventArgs.Empty); 
            }
            // восстановить форму курсора
            finally { Cursor.Current = cursor; }
        }
		///////////////////////////////////////////////////////////////////////
		private void OnTabControlChanged(object sender, EventArgs e)
		{
            // проверить наличие активной закладки
            if (tabControl.SelectedIndex < 0) return; 

			// получить активную закладку
			TabPage tabPage = tabControl.TabPages[tabControl.SelectedIndex]; 

			// обновить содержимое активной закладки
			((ContainersView)tabPage.Controls[0]).Refresh(); 

			// установить доступность кнопок
			info = null; buttonOK.Enabled = false; 
		}
		public void OnSelectContainer(SecurityInfo info)
		{
			// сохранить выбранный контейнер
			this.info = info; buttonOK.Enabled = (info != null); 
		}
		private void OnClickOK(object sender, EventArgs e)
		{
			// проверить необходимость действий
			if (callback == null) { DialogResult = DialogResult.OK; return; }

			// установить код возврата
			DialogResult = DialogResult.None;
			try { 
				// выполнить действие с выделенным объектом
				result = callback(this, info); DialogResult = DialogResult.OK;
			}
            // обработать отмену операции
            catch (OperationCanceledException) {}

			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(this, ex); }
		} 
		// созданный объект
		public object Result { get { return result; }}
	}
}
