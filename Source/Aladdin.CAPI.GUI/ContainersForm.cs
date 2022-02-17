using System;
using System.IO;
using System.Threading;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.Reflection;
using System.Security.Permissions;
using Aladdin.GUI; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Основное окно консоли
	///////////////////////////////////////////////////////////////////////////
	public partial class ContainersForm : ConsoleForm, PCSC.IReaderHandler
	{
		// отображаемые диалоги
		private FolderBrowserDialog	folderDialog;		// диалог выбора каталога	
		private OpenFileDialog		certificateDialog;	// диалог выбора сертификата
		private SaveFileDialog		requestDialog;		// диалог выбора запроса

		// обработчик прослушивания
		private Remoting.RemoteClientControl listener;

		// конструктор
        public ContainersForm(CryptoEnvironment environment) 
		{ 
			// создать корневой узел
			root = new Nodes.RootNode(environment); listener = null; 

			// указать начальный каталог
			string selectedPath = System.Environment.GetFolderPath(
				System.Environment.SpecialFolder.Personal
			); 
			// создать диалог выбора каталога
			folderDialog = new FolderBrowserDialog(); 

			// указать начальный каталог
			folderDialog.RootFolder   = System.Environment.SpecialFolder.Desktop;
			folderDialog.SelectedPath = selectedPath; 

			// задать параметры диалога выбора каталога
			folderDialog.Description = Resource.TitleDialogDirectory; 
			folderDialog.ShowNewFolderButton = false;

			// создать диалог выбора файла
			certificateDialog = new OpenFileDialog(); 
			certificateDialog.CheckFileExists = true; 
			
			// указать начальный каталог
			certificateDialog.InitialDirectory = selectedPath;

			// установить параметры диалога выбора файла
			certificateDialog.Title  = Resource.TitleOpenCertificateFile;
			certificateDialog.Filter = Resource.FilterCertificateFile;

			// создать диалог выбора файла
			requestDialog = new SaveFileDialog(); 
			requestDialog.OverwritePrompt = true; 
			
			// указать начальный каталог
			requestDialog.InitialDirectory = selectedPath;

			// установить параметры диалога выбора файла
			requestDialog.Title  = Resource.TitleSaveRequestFile;
			requestDialog.Filter = Resource.FilterRequestFile;
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
		// конструктор
		public ContainersForm() {} private Node root; 

		protected override void OnClosed(EventArgs e)
		{
			// завершить поток прослушивания считывателей
			base.OnClosed(e); if (listener != null) listener.Dispose();  
		}
		// имя формы
		protected override String GetName() { return Resource.CommonName; }

		// корневой узел
		protected override Node GetRootNode() { return root; } 

		///////////////////////////////////////////////////////////////////////
        // Диалоги выбора файлов и каталогов
		///////////////////////////////////////////////////////////////////////
        public string SelectDirectory(IWin32Window owner) 
        {
			// выбрать каталог контейнеров
			DialogResult result = folderDialog.ShowDialog(owner); 

			// проверить выбор диалога
			if (result != DialogResult.OK) return null; 

            // извлечь имя каталога
            return folderDialog.SelectedPath.ToLower(); 
        }
        public Certificate SelectCertificate(IWin32Window owner) 
        {
			// выбрать файл для запроса на сертификат
			DialogResult result = certificateDialog.ShowDialog(owner); 

			// проверить выбор файла
			if (result != DialogResult.OK) return null; 

			// выбрать файл для сохранения
			string file = certificateDialog.FileName; 

			// прочитать сертификат из файла
			return new Certificate(File.ReadAllBytes(file));
        }
        public string SelectRequestFile(IWin32Window owner) 
        {
			// выбрать файл для запроса на сертификат
			DialogResult result = requestDialog.ShowDialog(owner); 

			// вернуть выбранный файл
			return (result == DialogResult.OK) ? requestDialog.FileName: null; 
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
			// определить выделенный узел
			ConsoleNode node = SelectedNode; if (node == null) return; 

		    // установить форму курсора
		    Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor;
            try { 
                // выполнить задержку синхронизации 
                Thread.Sleep(5000); node.Refresh(); 
            }
            // восстановить форму курсора
            finally { Cursor.Current = cursor; }
        }
	    // удаление смарт-карты
	    public virtual void OnRemoveCard(PCSC.Reader reader) 
        {
			// определить выделенный узел
			ConsoleNode node = SelectedNode; if (node == null) return; 

		    // установить форму курсора
		    Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor;
            try { 
                // выполнить задержку синхронизации 
                Thread.Sleep(5000); node.Refresh(); 
            }
            // восстановить форму курсора
            finally { Cursor.Current = cursor; }
        }
		///////////////////////////////////////////////////////////////////////
		// Изображения
		///////////////////////////////////////////////////////////////////////
		protected override Icon GetIcon(string name)
		{
			// определить исполняемую сборку
			Assembly assembly = Assembly.GetExecutingAssembly();

			// определить имя приложения
			string applicationName = assembly.GetName().Name;

			// определить имя ресурса
			string resource = applicationName + ".Icons." + name;

			// вернуть найденный ресурс
			return new Icon(assembly.GetManifestResourceStream(resource)); 
		}
	}
}
