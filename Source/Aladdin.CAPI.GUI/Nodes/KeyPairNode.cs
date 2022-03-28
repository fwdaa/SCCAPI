using System;
using System.IO;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Security.Cryptography.X509Certificates;
using Aladdin.GUI;

namespace Aladdin.CAPI.GUI.Nodes
{
	///////////////////////////////////////////////////////////////////////////
	// Сертификат
	///////////////////////////////////////////////////////////////////////////
	internal class KeyPairNode : ConsoleForm.Node
	{
		private CryptoEnvironment environment; // криптографическая среда
        private CryptoProvider    provider;    // криптографический провайдер
		private ContainerKeyPair  keyPair;     // информация о ключевой паре

		// конструктор
		public KeyPairNode(CryptoEnvironment environment, 
			CryptoProvider provider, ContainerKeyPair keyPair) 
		{ 
			// сохранить переданные данные
			this.environment = environment; this.provider = provider; this.keyPair = keyPair;
		} 
		// отображаемые иконки
		public override string GetIcon(ConsoleNode node) { return "Keys.ico"; }
		// значение узла
		public override string Label { get 
        { 
            // вернуть имя субъекта сертификата
            if (keyPair.Certificate != null) return keyPair.Certificate.SubjectName; 

            // обработать исключительный случай
            if (keyPair.KeyID == null) return "?"; 

            // обработать частные случаи
            if (keyPair.KeyID.Length == 1 && keyPair.KeyID[0] == 1) return "AT_KEYEXCHANGE"; 
            if (keyPair.KeyID.Length == 1 && keyPair.KeyID[0] == 2) return "AT_SIGNATURE"; 

            // указать значение узла
            return Arrays.ToHexString(keyPair.KeyID); 
        }}
		// признак нераскрывающихся узлов
		public override bool IsLeaf { get { return true; }} 
		// признак допустимости удаления 
		public override bool CanDelete { get { return true; }}

		// обработать двойное нажатие
		public override void OnProperty(ConsoleNode node, object sender, EventArgs e) 
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

            // при наличии сертификата
            if (keyPair.Certificate != null)
            { 
			    // создать объект сертификата
			    X509Certificate2 cert = new X509Certificate2(keyPair.Certificate.Encoded); 

			    // отобразить сертификат
			    X509Certificate2UI.DisplayCertificate(cert, node.MainForm.Handle); 
            }
            else { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                {
                    // получить открытый ключ
                    IPublicKey publicKey = container.GetPublicKey(keyPair.KeyID); 

                    // создать диалог 
                    PublicKeyDialog dialog = new PublicKeyDialog(environment, publicKey); 

                    // отобразить диалог
                    dialog.ShowDialog(node.MainForm); 
                }
            }
		}
		// удалить объект
		public override void DeleteObject(ConsoleNode node) 
		{ 
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

			// указать способ аутентификации
			AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

			// получить интерфейс клиента
			using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
            {
		        // удалить ключевую пару
		        container.DeleteKeyPair(keyPair.KeyID); 
            }
		}
		// элементы контекстного меню для узла
		public override ToolStripItem[] GetContextMenuItems(ConsoleNode node) 
		{ 
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 

            // создать список элементов контекстного меню
            List<ToolStripItem> items = new List<ToolStripItem>(); 
            
			// указать способ аутентификации
			AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

			// получить интерфейс клиента
			using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
            {
                // получить допустимые способы использования открытого ключа
                KeyUsage keyUsage = container.GetKeyUsage(keyPair.KeyOID); 

                // при допустимости подписи добавить элемент меню
                if (KeyUsage.None != (keyUsage & KeyUsage.DigitalSignature | 
                        KeyUsage.CertificateSignature | KeyUsage.CrlSignature))
                { 
                    // указать возможность создания сертификата
                    items.Add(new ToolStripMenuItem(Resource.MenuCreateCertificate, null,    
                        delegate (object sender, EventArgs e) { OnCreateCertificate(node, sender, e); }
                    ));
                    // при наличии сертификата 
                    if (keyPair.Certificate != null) 
                    {
                        // указать возможность создания запроса на сертификат
                        items.Add(new ToolStripMenuItem(Resource.MenuCreateRequest, null,        
                            delegate (object sender, EventArgs e) { OnCreateRequest(node, sender, e); }
                        ));
                    }
                }
            }
            // указать возможность установки сертификата
			items.Add(new ToolStripMenuItem(Resource.MenuSetCertificate, null,    
                delegate (object sender, EventArgs e) { OnSetCertificate(node, sender, e); } 
            )); 
            return items.ToArray(); 
		}
		private void OnCreateCertificate(ConsoleNode node, object sender, EventArgs e)
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 
			try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                {
                    // получить допустимые способы использования открытого ключа
                    KeyUsage keyUsage = container.GetKeyUsage(keyPair.KeyOID); 

                    // создать диалог выбора параметров
                    CertRequestDialog dialog = new CertRequestDialog(keyUsage); 

                    // отобразить диалог выбора параметров
                    if (dialog.ShowDialog(mainForm) != DialogResult.OK) return; 

					// получить криптографическую культуру
					Culture culture = environment.GetCulture(keyPair.KeyOID); 

					// указать генератор случайных данных
					using (IRand rand = container.CreateRand())
					{ 
						// получить параметры алгоритма подписи
						ASN1.ISO.AlgorithmIdentifier signParameters = culture.SignDataAlgorithm(rand); 

						// создать самоподписанный сертификат 
						Certificate certificate = container.CreateSelfSignedCertificate( 
							rand, keyPair.KeyID, dialog.Subject, signParameters, dialog.NotBefore, dialog.NotAfter,   
							dialog.KeyUsage, dialog.ExtendedKeyUsage, dialog.BasicConstraints, null, null
						); 
						// сохранить измененную информацию
						keyPair = new ContainerKeyPair(keyPair.Info, keyPair.KeyID, keyPair.KeyOID, certificate); 
					}
                }
				// получить сообщение о завершении
				string message = Resource.StatusSetCertificate; node.Refresh(); 

				// вывести ее описание
				MessageBox.Show(mainForm, message, mainForm.Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); }
		}
		private void OnCreateRequest(ConsoleNode node, object sender, EventArgs e)
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 
			try { 
                // получить расширения сертификата
                ASN1.ISO.PKIX.Extensions extensions = keyPair.Certificate.Extensions; 

                // указать специальные расширения
                ASN1.ISO.PKIX.CE.BasicConstraints basicConstraints = 
                    (extensions != null) ? extensions.BasicConstraints : null; 

                // указать специальные расширения
                ASN1.ISO.PKIX.CE.CertificatePolicies certificatePolicies = 
                    (extensions != null) ? extensions.CertificatePolicies : null; 

				// выбрать файл для запроса на сертификат
				string fileName = mainForm.SelectRequestFile(mainForm); if (fileName == null) return;

				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

				// получить криптографическую культуру
				Culture culture = environment.GetCulture(keyPair.KeyOID); 

				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                {
					// создать генератор случайных данных
					using (IRand rand = container.CreateRand())
					{ 
						// получить параметры алгоритма подписи
						ASN1.ISO.AlgorithmIdentifier signParameters = culture.SignDataAlgorithm(rand); 

						// создать запрос на сертификат
						CertificateRequest request = container.CreateCertificateRequest( 
							rand, keyPair.KeyID, keyPair.Certificate.Subject, 
							signParameters, keyPair.Certificate.Extensions
						); 
						// сохранить запрос на сертификат в файл
						File.WriteAllBytes(fileName, request.Encoded); 
					}
                }
				// получить сообщение о завершении
				string message = Resource.StatusSaveRequestFile;

				// вывести ее описание
				MessageBox.Show(mainForm, message, mainForm.Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); }
		}
		private void OnSetCertificate(ConsoleNode node, object sender, EventArgs e)
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 
			try { 
				// прочитать сертификат из файла
				Certificate certificate = mainForm.SelectCertificate(mainForm);

                // проверить выбор сертификата
                if (certificate == null) return; 

				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(mainForm); 

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
						MessageBox.Show(mainForm, Resource.ErrorPublicKeyMismatch, 
							mainForm.Text, MessageBoxButtons.OK, MessageBoxIcon.Error); return; 
					}
					// изменить сертификат контейнера
					container.SetCertificate(keyPair.KeyID, certificate); 
                }
                // сохранить измененную информацию
                keyPair = new ContainerKeyPair(keyPair.Info, keyPair.KeyID, keyPair.KeyOID, certificate); 

				// получить сообщение о завершении
				string message = Resource.StatusSetCertificate; node.Refresh(); 

				// вывести ее описание
				MessageBox.Show(mainForm, message, mainForm.Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); }
		}
	}
}
