using System;
using System.Threading;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Security.Permissions;
using Aladdin.GUI; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Окно отображения ключей контейнеров
	///////////////////////////////////////////////////////////////////////////
	public partial class KeyPairsDialog : Form, PCSC.IReaderHandler
	{
		// функция проверки допустимости контейнера
		public delegate Object Callback(Form form, CryptoProvider provider, ContainerKeyPair keyPair); 

		private Callback	                 callback;	  // функция проверки допустимости
		private Remoting.RemoteClientControl listener;	  // поток прослушивания

        // выбранный элемент и значение функции обратного вызова
		private ContainerKeyPair keyPair; private object result;

		// отобразить диалог
		public static object Show(IWin32Window parent, 
            CryptoEnvironment environment, 
			Predicate<ContainerKeyPair> filter, Callback callback)
		{
			// создать диалог выбора контейнера
			KeyPairsDialog dialog = new KeyPairsDialog(environment, filter, callback); 

			// отобразить диалог
			DialogResult result = ModalView.Show(parent, dialog); 

			// проверить результат диалога
			if (result == DialogResult.OK) return dialog.Result;

			// при ошибке выбросить исключение
			throw new OperationCanceledException();
		}
        internal KeyPairsDialog(CryptoEnvironment environment, 
            Predicate<ContainerKeyPair> filter, Callback callback)
		{ 
			// инициализировать дочерние элементы
			InitializeComponent(); this.callback = callback;
			
			// для всех поддерживаемых провайдеров
			foreach (CryptoProvider provider in environment.Providers)
			{
				// добавить страницу закладок
				tabControl.TabPages.Add(CreateTabPage(
					tabTemplate, environment, provider, filter
				));
 			}
			// удалить фиктивную страницу
			tabControl.TabPages.Remove(tabTemplate); listener = null; 
            
			// проверить наличие закладок 
			if (tabControl.TabPages.Count == 0) throw new NotFoundException(); 

			// получить активную закладку
			TabPage tabPage = tabControl.TabPages[0]; 

			// обновить содержимое активной закладки
			((KeyPairsView)tabPage.Controls[0]).Refresh(); 
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
		public KeyPairsDialog() { InitializeComponent(); }

		protected override void OnClosed(EventArgs e)
		{
			// завершить поток прослушивания считывателей
			base.OnClosed(e); if (listener != null) listener.Dispose();  
		}
		private TabPage CreateTabPage(TabPage template, CryptoEnvironment environment, 
			CryptoProvider provider, Predicate<ContainerKeyPair> filter)
		{
			// создать страницу для провайдера
			KeyPairsView containersView = new KeyPairsView(this, environment, provider, filter); 

			// указать провайдер для страницы
			TabPage tabPage = new TabPage(); tabPage.Location = template.Location; 

			// указать параметры визуальной страницы
			tabPage.Padding = template.Padding; tabPage.Size = template.Size;	 

			// связать страницу с представлением 
			tabPage.Text = provider.Name; tabPage.Controls.Add(containersView); 
            
            // указать криптографический провайдер
            tabPage.Tag = provider; return tabPage;  
		}
		// вернуть область видимости
		public Scope Scope { get { return checkSystem.Checked ? CAPI.Scope.System : CAPI.Scope.Any; }}

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
			((KeyPairsView)tabPage.Controls[0]).Refresh(); 

			// установить доступность кнопок
			keyPair = null; buttonOK.Enabled = false; 
		}
		public void OnSelectKeyPair(ContainerKeyPair keyPair)
		{
			// сохранить выбранный контейнер
			this.keyPair = keyPair; buttonOK.Enabled = (keyPair != null); 
		}
		private void OnClickOK(object sender, EventArgs e)
		{
			// проверить необходимость действий
			if (callback == null) { DialogResult = DialogResult.OK; return; }

			// получить активную закладку
			TabPage tabPage = tabControl.TabPages[tabControl.SelectedIndex]; 

            // указать криптографический провайдер
            CryptoProvider provider = (CryptoProvider)tabPage.Tag; 

			// запретить закрытие диалога
			DialogResult = DialogResult.None; 
			try { 
				// выполнить действие с выделенным объектом
				result = callback(this, provider, keyPair); 
                
                // указать закрытие диалога
                DialogResult = DialogResult.OK;
			}
            // обработать отмену операции
            catch (OperationCanceledException) {}

			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(this, ex); }
		} 
		// значение функции обратного вызова
		public object Result { get { return result; }}
	}
}
