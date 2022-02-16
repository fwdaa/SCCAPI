using System;
using System.Collections.Generic;
using System.Windows.Forms;
using Aladdin.GUI; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог импорта ключевой пары
	///////////////////////////////////////////////////////////////////////////
	public partial class KeyImpDialog : Form
	{
		private CryptoEnvironment	environment;  // криптографическая среда
        private CryptoProvider		provider;     // криптографический провайдер
        private Type				storeType;    // тип хранилища контейнеров
		private SecurityInfo		storeInfo;	  // информация хранилища

		// конструктор
		public KeyImpDialog() { InitializeComponent(); }

		// конструктор
		public KeyImpDialog(CryptoEnvironment environment, 
			CryptoProvider provider, Type storeType, 
			SecurityInfo storeInfo, string containerName)
		{
			// сохранить переданные параметры
			InitializeComponent(); this.environment = environment; 

			// сохранить переданные параметры
			this.storeType = storeType; this.storeInfo = storeInfo; 
            
            // при указании имени контейнера
            this.provider = provider; if (containerName != null)
            {
                // указать имя контейнера
                textBoxName.Text = containerName; buttonImport.Enabled = true; 

			    // установить недоступность элементов
			    textBoxName.Enabled = checkBoxGUID.Enabled = false; 
            }
            else { buttonImport.Enabled = false; 

                // указать доступность элементов
                textBoxName.Enabled = checkBoxGUID.Enabled = true; 

                // обновить элементы управления
                OnNameChanged(this, EventArgs.Empty); 
            }
		}
		private void OnNameChanged(object sender, EventArgs e)
		{
		    // сформировать имя контейнера
            textBoxContainer.Text = String.Format("{0}\\{1}", storeInfo.FullName, textBoxName.Text);

			// проверить заполнение поля
			buttonImport.Enabled = (textBoxName.Text.Length != 0); 

        	// для файловых контейнеров
			if (typeof(Software.DirectoryStore).IsAssignableFrom(storeType) && textBoxName.Text.Length > 0)
            {
                // получить допустимые расширения
                string[] extensions = ((Software.CryptoProvider)provider).Extensions; 

                // для всех расширений
                bool hasExtension = false; foreach (string extension in extensions)
                {
                    // проверить наличие расширения в имени
                    if (textBoxName.Text.ToLower().EndsWith(extension)) { hasExtension = true; break; }
                }
                // при отсутствии расширения
                if (!hasExtension && extensions.Length > 0)
                {
                    // добавить расширение к имени
                    textBoxContainer.Text = String.Format("{0}.{1}", textBoxContainer.Text, extensions[0]); 
                }
            }
		}
		private void OnGuidChanged(object sender, EventArgs e)
		{
			// указать допустимость поля ввода имени
			textBoxName.Enabled = !checkBoxGUID.Checked; 
            
            // проверить необходимость генерации
            if (!checkBoxGUID.Checked) return; 

			// сгенерировать уникальное имя
			textBoxName.Text = Guid.NewGuid().ToString("B"); 
		}
		private void OnImportKeyPair(object sender, EventArgs e)
		{
			// изменить состояние курсора
			Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor; 
			try { 
                // запретить закрытие даалога
                DialogResult = DialogResult.None; 

                // указать начальные условия
				KeyUsage keyUsage = KeyUsage.None; KeyFlags keyFlags = KeyFlags.None; 

				// получить способ использования ключа
			    if (checkBoxDigitalSignature    .Checked) keyUsage |= KeyUsage.DigitalSignature; 
                if (checkBoxCertificateSignature.Checked) keyUsage |= KeyUsage.CertificateSignature; 
			    if (checkBoxCrlSignature        .Checked) keyUsage |= KeyUsage.CrlSignature; 
                if (checkBoxNonRepudiation      .Checked) keyUsage |= KeyUsage.NonRepudiation; 
			    if (checkBoxKeyEncipherment     .Checked) keyUsage |= KeyUsage.KeyEncipherment; 
                if (checkBoxKeyAgreement        .Checked) keyUsage |= KeyUsage.KeyAgreement; 
			    if (checkBoxDataEncipherment    .Checked) keyUsage |= KeyUsage.DataEncipherment; 

                // указать признак экспортируемости
                if (checkBoxExport.Checked) keyFlags = KeyFlags.Exportable; 

		        // определить имя контейнера
                object name = textBoxContainer.Text.Substring(textBoxContainer.Text.LastIndexOf('\\') + 1);

                // сформировать информацию об имени
                SecurityInfo containerInfo = new SecurityInfo(storeInfo.Scope, storeInfo.FullName, name); 

			    // функция проверки допустимости контейнера
			    KeyPairsDialog.Callback callback = delegate (
                    Form form, CryptoProvider keyProvider, ContainerKeyPair keyPair) 
			    {
					// указать способ выбора аутентификации 
					AuthenticationSelector selector = AuthenticationSelector.Create(form);

					// создать генератор случайных данных
					using (IRand rand = selector.CreateRand(keyProvider, null))
					{ 
						// импортировать ключи в контейнер
						return selector.ExportKeyPair(provider, containerInfo, 
							keyPair.KeyID, keyProvider, keyPair.Info, rand, keyUsage, keyFlags
						); 
					}
				}; 
				// перечислить фабрики алгоритмов
				using (Factories factories = environment.EnumerateFactories())
				{ 
					// создать диалог выбора контейнера
					KeyPairsDialog dialog = new KeyPairsDialog(
						environment, factories.Providers, null, callback
					); 
					// отобразить диалог выбора контейнера
					if (dialog.ShowDialog(this) != DialogResult.OK) return; 
				}
				// получить сообщение
				string message = Resource.StatusImportPair; 

				// вывести сообщение
				MessageBox.Show(this, message, Text, MessageBoxButtons.OK, MessageBoxIcon.Information);  

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
