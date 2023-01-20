using System;
using System.Globalization; 
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;

namespace Aladdin.CAPI.GUI
{
	//////////////////////////////////////////////////////////////////////////////
	// Закладка диалога сертификатов контейнера
	//////////////////////////////////////////////////////////////////////////////
	public partial class KeyPairsView : UserControl
	{
		private KeyPairsDialog              parent;	     // родительский диалог
		private CryptoEnvironment			environment; // криптографическая среда
		private CryptoProvider              provider;	 // криптографический провайдер
		private Predicate<ContainerKeyPair> filter;	     // фильтр выбора ключей

		public KeyPairsView(KeyPairsDialog parent, CryptoEnvironment environment, 
            CryptoProvider provider, Predicate<ContainerKeyPair> filter) 
		{
			// выполнить инициализацию
			InitializeComponent(); this.parent = parent; this.filter = filter; 
			
			// сохранить переданные параметры
			this.environment = environment; this.provider = provider; 
			
			// создать элементы контекстного меню
			ToolStripItem itemShow = new ToolStripMenuItem(Resource.MenuProperties, null, OnDoubleClick); 

			// указать контекстное меню
			listView.ContextMenuStrip = new ContextMenuStrip(); 
			listView.ContextMenuStrip.Items.AddRange(new ToolStripItem[] { itemShow }); 

			// указать элемент по умолчанию
			listView.ContextMenuStrip.Items[0].Select(); 
		}
		public KeyPairsView() { InitializeComponent(); }

		// обновить список ключевых пар
		public new bool Refresh() 
		{ 
			// очистить список сертификатов
			Scope scope = parent.Scope; listView.Items.Clear();
		 
			// сделать контекстное меню доступным/недоступным
			OnSelectedIndexChanged(this, EventArgs.Empty); 

			// указать способ аутентификации
			AuthenticationSelector selector = AuthenticationSelector.Create(
				parent, environment.AuthenticationAttempts
			); 
            // для всех контейнеров
            foreach (SecurityInfo info in provider.EnumerateAllObjects(scope))
            { 
				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, info, selector))
				try { 
					// перечислить пары ключей контейнера
					ContainerKeyPair[] keyPairs = container.EnumerateKeyPairs(); 

   					// для всех пар ключей
					foreach (ContainerKeyPair keyPair in keyPairs)
					{
						// заполнить описание
						if (filter == null || filter(keyPair)) PopulateView(keyPair); 
					}
				}
				catch {}
            }
			// установить размер столбца
			listView.Columns[listView.Columns.Count - 1].Width = -1; 

            // вернуть признак наличия элементов
            return listView.Items.Count > 0;
		}
		private void PopulateView(ContainerKeyPair keyPair)
		{
            // получить имя контейнера
            String name = keyPair.Info.FullName; string subject = "?"; 

    	    // указать начальные условия
		    string notBefore = "N/A"; string notAfter = "N/A";

            // при наличии сертификата
            if (keyPair.CertificateChain != null && keyPair.CertificateChain[0] != null)
            {
                // извлечь сертификат
                Certificate certificate = keyPair.CertificateChain[0]; subject = certificate.SubjectName;

			    // определить начало срока действия
			    notBefore = certificate.NotBefore.ToString("d", CultureInfo.CurrentUICulture); 

			    // определить окончание срока действия
			    notAfter = certificate.NotAfter.ToString("d", CultureInfo.CurrentUICulture); 
            }
            // при указании идентикатора ключа
            else if (keyPair.KeyID != null)
            {
                // указать имя субъекта
                if (keyPair.KeyID.Length == 1 && keyPair.KeyID[0] == 1) subject = "AT_KEYEXCHANGE"; else
                if (keyPair.KeyID.Length == 1 && keyPair.KeyID[0] == 2) subject = "AT_SIGNATURE"  ; else
                
                // указать имя субъекта
                subject = Arrays.ToHexString(keyPair.KeyID); 
            }
    	    // указать информацию о новом элементе в список
		    ListViewItem item = new ListViewItem(new string[] { subject, notBefore, notAfter, name });

		    // указать строку подсказки
		    item.ToolTipText = String.Format("{0} {1} {2} {3}", subject, notBefore, notAfter, name); 

            // добавить созданную информацию
		    item.Tag = keyPair; listView.Items.Add(item); 
		}
		private void OnSelectedIndexChanged(object sender, EventArgs e)
		{
			// определить допустимость действий
			bool selected = listView.SelectedItems.Count != 0; 

			// сделать контекстное меню доступным/недоступным
			listView.ContextMenuStrip.Items[0].Enabled = selected; 

			// оповестить родительский диалог
			if (!selected) parent.OnSelectKeyPair(null);
            else { 
                // выполнить преобразование типа
                ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 

			    // оповестить родительский диалог
			    parent.OnSelectKeyPair(keyPair); 
            }
		}
		private void OnDoubleClick(object sender, EventArgs e)
		{
			// получить выделенный элемент
			ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 

            // при наличии сертификата
            if (keyPair.CertificateChain != null && keyPair.CertificateChain[0] != null)
            { 
			    // отобразить сертификат
			    CertificateDialog.Show(Handle, keyPair.CertificateChain); 
            }
            else { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					parent, environment.AuthenticationAttempts
				); 
				// получить интерфейс клиента
				using (ClientContainer client = new ClientContainer(provider, keyPair.Info, selector))
				{ 
					// получить открытый ключ
					IPublicKey publicKey = client.GetPublicKey(keyPair.KeyID); 

					// создать диалог 
					PublicKeyDialog dialog = new PublicKeyDialog(environment, publicKey); 

					// отобразить диалог
					dialog.ShowDialog(Parent); 
				}
            }
			// оповестить родительский диалог
			parent.OnSelectKeyPair(keyPair);
		} 
	}
}
