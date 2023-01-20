using System;
using System.IO;
using System.Collections.Generic;
using System.Windows.Forms;
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
            // при наличии сертификата
            if (keyPair.CertificateChain != null && keyPair.CertificateChain[0] != null) 
			{
				// вернуть имя субъекта сертификата
				return keyPair.CertificateChain[0].SubjectName; 
			}
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
            if (keyPair.CertificateChain != null && keyPair.CertificateChain[0] != null)
            { 
			    // отобразить сертификат
				CertificateDialog.Show(node.MainForm.Handle, keyPair.CertificateChain); 
            }
            else { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					mainForm, environment.AuthenticationAttempts
				); 
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
			AuthenticationSelector selector = AuthenticationSelector.Create(
				mainForm, environment.AuthenticationAttempts
			); 
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
            List<ToolStripItem> items = new List<ToolStripItem>(); int check = 0; 
            
			// указать способ аутентификации
			AuthenticationSelector selector = AuthenticationSelector.Create(
				mainForm, environment.AuthenticationAttempts
			); 
			// получить интерфейс клиента
			using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
            {
                // получить допустимые способы использования открытого ключа
                KeyUsage keyUsage = container.GetKeyUsage(keyPair.KeyOID); 

                // при допустимости подписи 
                if (KeyUsage.None != (keyUsage & KeyUsage.DigitalSignature | 
                        KeyUsage.CertificateSignature | KeyUsage.CrlSignature)) 
				{ 
                    // указать возможность создания сертификата
                    items.Add(new ToolStripMenuItem(Resource.MenuCreateCertificate, null,    
                        delegate (object sender, EventArgs e) { OnCreateCertificate(node, sender, e); }
                    ));
				}
				// при наличии сертификата
				if (keyPair.CertificateChain != null && keyPair.CertificateChain[0] != null)
                {
					// при допустимости подписи 
					if (KeyUsage.None != (keyUsage & KeyUsage.DigitalSignature | 
							KeyUsage.CertificateSignature | KeyUsage.CrlSignature)) { check = 2; 
                    
                        // указать возможность создания запроса на сертификат
                        items.Add(new ToolStripMenuItem(Resource.MenuCreateRequest, null,        
                            delegate (object sender, EventArgs e) { OnCreateRequest(node, sender, e); }
                        ));
                    }
					// при допустимости шифрования 
					if (KeyUsage.None != (keyUsage & (KeyUsage.KeyEncipherment | 
						KeyUsage.KeyAgreement | KeyUsage.DataEncipherment))) check = 1;
                }
            }
            // указать возможность установки сертификата
			items.Add(new ToolStripMenuItem(Resource.MenuSetCertificate, null,    
                delegate (object sender, EventArgs e) { OnSetCertificate(node, sender, e); } 
            )); 
			// указать возможность проверки сертификата
			if (check == 1) items.Add(new ToolStripMenuItem(Resource.MenuCheckAccess, null,    
				delegate (object sender, EventArgs e) { OnTestEncrypt(node, sender, e); }
			));
			// указать возможность создания сертификата
			if (check == 2) items.Add(new ToolStripMenuItem(Resource.MenuCheckAccess, null,    
				delegate (object sender, EventArgs e) { OnTestSign(node, sender, e); }
			));
            return items.ToArray(); 
		}
		private void OnTestEncrypt(ConsoleNode node, object sender, EventArgs e)
        {
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 
			try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					mainForm, environment.AuthenticationAttempts
				); 
				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                {
					// получить криптографическую культуру
					Culture culture = environment.GetCulture(keyPair.KeyOID); 

					// указать используемый сертификат
					Certificate certificate = keyPair.CertificateChain[0]; 

					// создать список сертификатов
					Certificate[] recipientCertificates = new Certificate[] { certificate }; 

					// закодировать данные
					CMSData cmsData = new CMSData(ASN1.ISO.PKCS.PKCS7.OID.data, new byte[0]); 

                    // указать генератор случайных данных
                    using (IRand rand = environment.CreateRand(null))
                    { 
						// зашифровать данные
						byte[] encrypted = container.EncryptData(
							rand, culture, certificate, recipientCertificates, cmsData, null
						); 
						// расшифровать данные
						container.DecryptData(encrypted); 
					}
                }
				// получить сообщение о завершении
				string message = Resource.StatusAccessGranted; node.Refresh(); 

				// вывести ее описание
				MessageBox.Show(mainForm, message, mainForm.Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); }
        }
		private void OnTestSign(ConsoleNode node, object sender, EventArgs e)
        {
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 
			try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					mainForm, environment.AuthenticationAttempts
				); 
				// получить интерфейс клиента
				using (ClientContainer container = new ClientContainer(provider, keyPair.Info, selector))
                {
					// получить криптографическую культуру
					Culture culture = environment.GetCulture(keyPair.KeyOID); 

					// указать используемый сертификат
					Certificate certificate = keyPair.CertificateChain[0]; 

					// закодировать данные
					CMSData cmsData = new CMSData(ASN1.ISO.PKCS.PKCS7.OID.data, new byte[0]); 

                    // указать генератор случайных данных
                    using (IRand rand = environment.CreateRand(null))
                    { 
						// подписать данные данные
						container.SignData(rand, culture, certificate, cmsData, null, null); 
					}
                }
				// получить сообщение о завершении
				string message = Resource.StatusAccessGranted; node.Refresh(); 

				// вывести ее описание
				MessageBox.Show(mainForm, message, mainForm.Text, 
					MessageBoxButtons.OK, MessageBoxIcon.Information);  
			}
			// при ошибке вывести ее описание
			catch (Exception ex) { ErrorDialog.Show(mainForm, ex); }
        }
		private void OnCreateCertificate(ConsoleNode node, object sender, EventArgs e)
		{
			// получить основное окно
			ContainersForm mainForm = (ContainersForm)node.MainForm; 
			try { 
				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					mainForm, environment.AuthenticationAttempts
				); 
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
						// создать цепочку сертификатов
						Certificate[] certificateChain = new Certificate[] { certificate }; 

						// сохранить измененную информацию
						keyPair = new ContainerKeyPair(keyPair.Info, keyPair.KeyID, keyPair.KeyOID, certificateChain); 
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
                ASN1.ISO.PKIX.Extensions extensions = keyPair.CertificateChain[0].Extensions; 

                // указать специальные расширения
                ASN1.ISO.PKIX.CE.BasicConstraints basicConstraints = 
                    (extensions != null) ? extensions.BasicConstraints : null; 

                // указать специальные расширения
                ASN1.ISO.PKIX.CE.CertificatePolicies certificatePolicies = 
                    (extensions != null) ? extensions.CertificatePolicies : null; 

				// выбрать файл для запроса на сертификат
				string fileName = mainForm.SelectRequestFile(mainForm); if (fileName == null) return;

				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					mainForm, environment.AuthenticationAttempts
				); 
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
							rand, keyPair.KeyID, keyPair.CertificateChain[0].Subject, 
							signParameters, keyPair.CertificateChain[0].Extensions
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

				// создать цепочку сертификатов
				Certificate[] certificateChain = new Certificate[] { certificate }; 

				// указать способ аутентификации
				AuthenticationSelector selector = AuthenticationSelector.Create(
					mainForm, environment.AuthenticationAttempts
				); 
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
					container.SetCertificateChain(keyPair.KeyID, certificateChain); 
                }
                // сохранить измененную информацию
                keyPair = new ContainerKeyPair(keyPair.Info, keyPair.KeyID, keyPair.KeyOID, certificateChain); 

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
