using System;
using System.IO;
using System.Windows.Forms;
using Aladdin.GUI; 

namespace Aladdin.CAPI.GUI
{
	///////////////////////////////////////////////////////////////////////////
	// Диалог генерации ключевой пары
	///////////////////////////////////////////////////////////////////////////
	public partial class KeyGenDialog : Form
	{
        private CryptoEnvironment environment; // криптографическая среда
        private CryptoProvider    provider;    // криптографический провайдер
        private Type              storeType;   // тип хранилища контейнеров
		private SecurityInfo      storeInfo;   // информация хранилища

		// конструктор
		public KeyGenDialog() { InitializeComponent(); }

		// конструктор
		public KeyGenDialog(CryptoEnvironment environment, CryptoProvider provider, 
            Type storeType, SecurityInfo storeInfo, string containerName)
		{
			// сохранить переданные параметры
			InitializeComponent(); this.environment = environment; 
			
			// сохранить переданные параметры
			this.storeType = storeType; this.storeInfo = storeInfo; 
            
            // сохранить переданные параметры
            this.provider = provider; checkBoxExport.Checked = false; 
            
            // указать допустимость изменения признака экспортируемости
            checkBoxExport.Enabled = !(provider is Software.CryptoProvider);

            // указать имя контейнера
            if (containerName != null) { textBoxName.Text = containerName; 
            
			    // установить недоступность элементов
			    textBoxName.Enabled = checkBoxGUID.Enabled = false;
            }
            // указать доступность элементов
            else { textBoxName.Enabled = checkBoxGUID.Enabled = true; 

                // обновить элементы управления
                OnNameChanged(this, EventArgs.Empty); 
            }
		}
        private void OnLoad(object sender, EventArgs e)
        {
            // указать способ выбора аутентификации 
            AuthenticationSelector selector = AuthenticationSelector.Create(this);

            // открыть хранилище объектов
            using (SecurityStore store = (SecurityStore)selector.OpenObject(
                provider, storeInfo.Scope, storeInfo.FullName, FileAccess.Read))
            { 
                // для всех допустимых ключей
                foreach (string key in provider.GeneratedKeys(store))
                {
                    // определить отображаемое имя ключа
                    string keyName = environment.GetKeyName(key); if (keyName == key) continue; 
                    
                    // добавить ключ в список
                    comboBoxKeyOID.Items.Add(new KeyItem(keyName, key)); 
                }
            }
			// перейти на первый элемент
			comboBoxKeyOID.SelectedIndex = 0;
        }
		private void OnNameChanged(object sender, EventArgs e)
		{
		    // сформировать имя контейнера
            textBoxContainer.Text = String.Format("{0}\\{1}", storeInfo.FullName, textBoxName.Text);

			// проверить заполнение поля
			buttonGenerate.Enabled = (textBoxName.Text.Length != 0); 

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
		private void OnKeyOidChanged(object sender, EventArgs e)
		{
			// определить выбранный ключ
			KeyItem key = (KeyItem)comboBoxKeyOID.Items[comboBoxKeyOID.SelectedIndex]; 

			// сбросить допустимый выбор
			checkBoxDigitalSignature    .Checked = false; checkBoxCertificateSignature.Checked = false;
			checkBoxCrlSignature        .Checked = false; checkBoxNonRepudiation      .Checked = false;
			checkBoxKeyEncipherment     .Checked = false; checkBoxKeyAgreement        .Checked = false;
			checkBoxDataEncipherment    .Checked = false; 

            // указать способ выбора аутентификации 
            AuthenticationSelector selector = AuthenticationSelector.Create(this);
            try { 
                // открыть хранилище объектов
                using (SecurityStore store = (SecurityStore)selector.OpenObject(
                    provider, storeInfo.Scope, storeInfo.FullName, FileAccess.Read))
                {
                    // получить способ использования ключа
                    KeyUsage keyUsage = provider.GetKeyFactory(key.OID).GetKeyUsage(); 

			        // указать допустимый выбор
			        checkBoxDigitalSignature    .Enabled = ((keyUsage & KeyUsage.DigitalSignature    ) != KeyUsage.None); 
			        checkBoxCertificateSignature.Enabled = ((keyUsage & KeyUsage.CertificateSignature) != KeyUsage.None); 
			        checkBoxCrlSignature        .Enabled = ((keyUsage & KeyUsage.CrlSignature        ) != KeyUsage.None); 
			        checkBoxNonRepudiation      .Enabled = ((keyUsage & KeyUsage.NonRepudiation      ) != KeyUsage.None); 
			        checkBoxKeyEncipherment     .Enabled = ((keyUsage & KeyUsage.KeyEncipherment     ) != KeyUsage.None); 
			        checkBoxKeyAgreement        .Enabled = ((keyUsage & KeyUsage.KeyAgreement        ) != KeyUsage.None); 
			        checkBoxDataEncipherment    .Enabled = ((keyUsage & KeyUsage.DataEncipherment    ) != KeyUsage.None); 
                }
            }
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(this, ex); }
		}
		private void OnGenerateKeyPair(object sender, EventArgs e)
		{
			// изменить состояние курсора
			Cursor cursor = Cursor.Current; Cursor.Current = Cursors.WaitCursor; 
			try { 
                // запретить закрытие диалога
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

			    // определить выбранный ключ
			    KeyItem key = (KeyItem)comboBoxKeyOID.Items[comboBoxKeyOID.SelectedIndex]; 

		        // определить имя контейнера
                object name = textBoxContainer.Text.Substring(textBoxContainer.Text.LastIndexOf('\\') + 1);

                // сформировать информацию об имени
                SecurityInfo containerInfo = new SecurityInfo(storeInfo.Scope, storeInfo.FullName, name); 

                // указать способ выбора аутентификации 
                AuthenticationSelector selector = AuthenticationSelector.Create(this);

                // создать генератор случайных данных
                using (IRand rand = selector.CreateRand(provider, null))
                { 
     	            // сгенерировать пару ключей в контейнере
                    selector.GenerateKeyPair(provider, containerInfo, rand, environment, key.OID, keyUsage, keyFlags); 
                }
        		// получить сообщение
				string message = Resource.StatusGeneratePair; 

				// вывести сообщение
				MessageBox.Show(this, message, Text, MessageBoxButtons.OK, MessageBoxIcon.Information);  

                // указать закрытие диалога
                DialogResult = DialogResult.OK; 
			}
			// проверить отмену операции
			catch (OperationCanceledException) {}

			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(this, ex); }

			// восстановить состояние курсора
			finally { Cursor.Current = cursor; }
		}
        ///////////////////////////////////////////////////////////////////////
        // Описание идентификатора OID в списке
        ///////////////////////////////////////////////////////////////////////
        private class KeyItem
        {
            // конструктор
            public KeyItem(string name, string oid) { Name = name; OID = oid; }

            // имя и значение идентификатора
            public readonly string Name; public readonly string OID;

            // строковое представление
            public override string ToString() 
            { 
                // вернуть строковое представление
                return String.Format("{0} ({1})", Name, OID); 
            }
        }
	}
}
