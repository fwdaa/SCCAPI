using System;
using System.IO;
using System.Windows.Forms;

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Окно отображения контейнера
	///////////////////////////////////////////////////////////////////////////
	public partial class ContainerDialog : Form
	{
		// отображаемые диалоги
		private OpenFileDialog certificateDialog;	// диалог выбора сертификата
		private SaveFileDialog requestDialog;		// диалог выбора запроса

		// показать дивалог
		public static void Show(IWin32Window parent, 
            CryptoEnvironment environment, CryptoProvider provider, SecurityInfo info)
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
			ContainerDialog dialog = new ContainerDialog( 
                environment, provider, info, certificateDialog, requestDialog
			); 
            // отобразить диалог
            Aladdin.GUI.ModalView.Show(parent, dialog); 
		}
		internal ContainerDialog(CryptoEnvironment environment, CryptoProvider provider, 
            SecurityInfo info, OpenFileDialog certificateDialog, SaveFileDialog requestDialog) 
		{ 
			// сохранить переданные параметры
			InitializeComponent(); this.certificateDialog = certificateDialog; this.requestDialog = requestDialog; 
            
			// создать страницу для провайдера
            ContainerView view = new ContainerView(this, environment, provider, info); 

			// указать параметры визуальной страницы
			TabPage tabPage = new TabPage(); tabPage.Location = tabTemplate.Location; 

			// указать параметры визуальной страницы
			tabPage.Padding = tabTemplate.Padding; tabPage.Size = tabTemplate.Size;	 

			// связать страницу с представлением 
			tabPage.Text = info.Name.ToString(); tabPage.Controls.Add(view); 

			// удалить фиктивную страницу
			tabControl.TabPages.Add(tabPage); tabControl.TabPages.Remove(tabTemplate); 
		}
		public ContainerDialog() { InitializeComponent(); }

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
		public string SelectRequestFile(IWin32Window window)
		{
			// выбрать файл для запроса на сертификат
			DialogResult result = requestDialog.ShowDialog(window); 

			// вернуть имя файла
			return (result == DialogResult.OK) ? requestDialog.FileName : null; 
		}
	}
}
