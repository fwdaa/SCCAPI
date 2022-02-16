using System;
using System.IO;
using System.Globalization; 
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI
{
	//////////////////////////////////////////////////////////////////////////////
	// Закладка диалога контейнера
	//////////////////////////////////////////////////////////////////////////////
	public partial class ContainerView : UserControl
	{
		private ContainerDialog		parent;		 // родительский диалог
		private CryptoEnvironment	environment; // криптографическая среда
        private CryptoProvider		provider;    // криптографический провайдер
		private SecurityInfo		info;	     // информация о контейнере
		
		public ContainerView(ContainerDialog parent, 
			CryptoEnvironment environment, CryptoProvider provider, SecurityInfo info) 
		{ 
			// сохранить переданные параметры
			InitializeComponent(); this.parent = parent; this.info = info; 
            
			// сохранить переданные параметры
            this.environment = environment; this.provider = provider; 

			// создать элементы контекстного меню
			ToolStripItem itemShow    = new ToolStripMenuItem(Resource.MenuProperties,        null, OnDoubleClick       ); 
			ToolStripItem itemCert    = new ToolStripMenuItem(Resource.MenuCreateCertificate, null, OnCreateCertificate ); 
			ToolStripItem itemRequest = new ToolStripMenuItem(Resource.MenuCreateRequest,     null, OnCreateRequest	    ); 
			ToolStripItem itemChange  = new ToolStripMenuItem(Resource.MenuSetCertificate,    null, OnSetCertificate    ); 
			ToolStripItem itemDelete  = new ToolStripMenuItem(Resource.MenuDeleteKeyPair,     null, OnDeleteKeyPair     ); 

			// указать контекстное меню
			listView.ContextMenuStrip = new ContextMenuStrip(); 
			listView.ContextMenuStrip.Items.AddRange(new ToolStripItem[] { 
				itemShow, new ToolStripSeparator(), itemRequest, itemChange, itemDelete
			}); 
			// указать элемент по умолчанию
			listView.ContextMenuStrip.Items[0].Select(); Refresh(); 
		}
		public ContainerView() { InitializeComponent(); }

		// обновить список ключевых пар
		public new void Refresh() 
        { 
            try { listView.Items.Clear();
 
			    // сделать контекстное меню доступным/недоступным
			    OnSelectedIndexChanged(this, EventArgs.Empty); 

				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(parent); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, info, selector))
				{ 
					// перечислить пары ключей контейнера
					ContainerKeyPair[] keyPairs = container.EnumerateKeyPairs(); 

					// заполнить представление
					foreach (ContainerKeyPair keyPair in keyPairs) PopulateView(keyPair);
                }
            }
            catch {}
		}
		private void PopulateView(ContainerKeyPair keyPair)
		{
    	    // указать начальные условия
		    string subject = "?"; string notBefore = "N/A"; string notAfter = "N/A";

            // при наличии сертификата
            string keyUsage = String.Empty; if (keyPair.Certificate != null)
            {
                // извлечь сертификат
                Certificate certificate = keyPair.Certificate; subject = certificate.SubjectName;

			    // определить начало срока действия
			    notBefore = certificate.NotBefore.ToString("d", CultureInfo.CurrentUICulture); 

			    // определить окончание срока действия
			    notAfter = certificate.NotAfter.ToString("d", CultureInfo.CurrentUICulture); 

                // получить описание способа использования
                keyUsage = Reflection.GetDescription(certificate.KeyUsage); 
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
		    ListViewItem item = new ListViewItem(new string[] { subject, notBefore, notAfter, keyUsage});

		    // указать строку подсказки
		    item.ToolTipText = String.Format("{0} {1} {2} {3}", subject, notBefore, notAfter, keyUsage); 

            // добавить созданную информацию
		    item.Tag = keyPair; listView.Items.Add(item); 
		}
		private void OnSelectedIndexChanged(object sender, EventArgs e)
		{
            // проверить допустимость действий
            if (listView.SelectedItems.Count == 0)
            {
			    // сделать контекстное меню недоступным
			    listView.ContextMenuStrip.Items[0].Enabled = false; 
			    listView.ContextMenuStrip.Items[1].Enabled = false; 
			    listView.ContextMenuStrip.Items[2].Enabled = false; 
			    listView.ContextMenuStrip.Items[3].Enabled = false; 
			    listView.ContextMenuStrip.Items[4].Enabled = false; 
            }
            else {
			    // получить выделенный элемент
			    ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 

				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(parent); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
				{ 
					// получить способ использования ключа
					KeyUsage keyUsage = container.GetKeyUsage(keyPair.KeyOID); 

					// при отсутствии возможности подписи
					if (KeyUsage.None == (keyUsage & (KeyUsage.DigitalSignature | 
						KeyUsage.CertificateSignature | KeyUsage.CrlSignature)))
					{
						// сделать контекстное меню недоступным
						listView.ContextMenuStrip.Items[1].Enabled = false; 
						listView.ContextMenuStrip.Items[2].Enabled = false; 
					}
					// при отсутствии сертификата
					else if (keyPair.Certificate == null)
					{
						// сделать контекстное меню доступным
						listView.ContextMenuStrip.Items[1].Enabled = true; 
						listView.ContextMenuStrip.Items[2].Enabled = false; 
					}
					else {
						// сделать контекстное меню доступным
						listView.ContextMenuStrip.Items[1].Enabled = true; 
						listView.ContextMenuStrip.Items[2].Enabled = true; 
					}
				}
			    // сделать контекстное меню доступным
		        listView.ContextMenuStrip.Items[3].Enabled = true; 
			    listView.ContextMenuStrip.Items[4].Enabled = true;
            }
		}
		private void OnDoubleClick(object sender, EventArgs e)
		{
    	    // получить выделенный элемент
		    ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 

            // при наличии сертификата
            if (keyPair.Certificate != null)
            { 
			    // создать объект сертификата
			    X509Certificate2 cert = new X509Certificate2(keyPair.Certificate.Encoded); 

			    // отобразить сертификат
			    X509Certificate2UI.DisplayCertificate(cert, Handle); 
            }
            else { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(parent); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                {
					// получить открытый ключ
					IPublicKey publicKey = container.GetPublicKey(keyPair.KeyID); 

					// создать диалог 
					PublicKeyDialog dialog = new PublicKeyDialog(environment, publicKey); 

					// отобразить диалог
					dialog.ShowDialog(Parent); 
                }
            }
		}
		private void OnCreateCertificate(object sender, EventArgs e)
		{
            // получить выделенный элемент
		    ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 
			try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(parent); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                { 
					// получить способ использования ключа
					KeyUsage keyUsage = container.GetKeyUsage(keyPair.KeyOID); 

					// создать диалог выбора параметров
					CertRequestDialog dialog = new CertRequestDialog(keyUsage); 

					// отобразить диалог выбора параметров
					if (dialog.ShowDialog(parent) != DialogResult.OK) return; 

					// указать генератор случайных данных
					using (IRand rand = container.CreateRand())
					{ 
						// создать самоподписанный сертификат
						Certificate certificate = container.CreateSelfSignedCertificate(rand,  
							keyPair.KeyID, dialog.Subject, null, dialog.NotBefore, dialog.NotAfter,  
							dialog.KeyUsage, dialog.ExtendedKeyUsage, dialog.BasicConstraints, null, null
						); 
						// сохранить измененную информацию
						listView.SelectedItems[0].Tag = new ContainerKeyPair(
							keyPair.Info, keyPair.KeyID, keyPair.KeyOID, certificate 
						);
					}
                }
				// получить сообщение о завершении
				string message = Resource.StatusSetCertificate; Refresh(); 

				// вывести ее описание
				MessageBox.Show(parent, message, Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(parent, ex); }
		}
		public void OnCreateRequest(object sender, EventArgs e)
		{
            // получить выделенный элемент
		    ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 

			// выбрать файл для сохранения
			string file = parent.SelectRequestFile(parent); if (file == null) return;
            try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(parent); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                { 
					// создать генератор случайных данных
					using (IRand rand = container.CreateRand())
					{ 
						// сгенерировать запрос на сертификат
						CertificateRequest request = container.CreateCertificateRequest( 
							null, keyPair.KeyID, keyPair.Certificate.Subject, 
							null, keyPair.Certificate.Extensions
						); 
						// сохранить запрос на сертификат в файл
						File.WriteAllBytes(file, request.Encoded); 
					}
				}
				// получить сообщение о завершении
				string message = Resource.StatusSaveRequestFile;

				// вывести ее описание
				MessageBox.Show(parent, message, Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(parent, ex); }
		}
		public void OnSetCertificate(object sender, EventArgs e)
		{
            // получить выделенный элемент
		    ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 
			try { 
				// прочитать сертификат из файла
				Certificate certificate = parent.SelectCertificate(parent);

                // проверить выбор сертификата
                if (certificate == null) return; 

				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(parent); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                { 
					// получить открытый ключ
					IPublicKey publicKey = container.GetPublicKey(keyPair.KeyID); 

					// закодировать открытый ключ
					ASN1.ISO.PKIX.SubjectPublicKeyInfo keyInfo = publicKey.Encoded; 

					// проверить соответствие ключей
					if (!keyInfo.Equals(certificate.PublicKeyInfo))
					{
						// вывести описание ошибки
						MessageBox.Show(parent, Resource.ErrorPublicKeyMismatch, 
							Text, MessageBoxButtons.OK, MessageBoxIcon.Error); return; 
					}
					// изменить сертификат в контейнере
					container.SetCertificate(keyPair.KeyID, certificate); 
                }
                // сохранить измененную информацию
                listView.SelectedItems[0].Tag = new ContainerKeyPair(
                    keyPair.Info, keyPair.KeyID, keyPair.KeyOID, certificate 
                ); 
				// получить сообщение о завершении
				string message = Resource.StatusSetCertificate; Refresh(); 

				// вывести ее описание
				MessageBox.Show(parent, message, Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(parent, ex); }
		}
		public void OnDeleteKeyPair(object sender, EventArgs e)
		{
            // получить выделенный элемент
		    ContainerKeyPair keyPair = (ContainerKeyPair)listView.SelectedItems[0].Tag; 
			try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(parent); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                { 
					// удалить ключевую пару контейнера
					container.DeleteKeyPair(keyPair.KeyID); 
				}
				// получить сообщение о завершении
				string message = Resource.StatusDeleteKeyPairs; Refresh(); 

				// вывести ее описание
				MessageBox.Show(parent, message, Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(parent, ex); }
        }
	}
}
