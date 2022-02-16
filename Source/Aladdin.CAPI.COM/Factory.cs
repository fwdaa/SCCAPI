using System;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Diagnostics.CodeAnalysis; 
using Aladdin.GUI; 

namespace Aladdin.CAPI.COM
{
	///////////////////////////////////////////////////////////////////////////
	// Фабрика алгоритмов 
	///////////////////////////////////////////////////////////////////////////
    [ClassInterface(ClassInterfaceType.None)]
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Factory : RefObject, IFactory
	{
        // среда окружения и локализация
		private CryptoEnvironment environment; private CultureInfo cultureInfo;

		// конструктор
		public Factory(CultureInfo cultureInfo, string file) 
		{ 
			// сохранить переданные параметры
			this.cultureInfo = cultureInfo; 
                
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try { 
				// прочитать конфигурацию
			    environment = new CryptoEnvironment(file);
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            environment.Dispose(); base.OnDispose(); 
        }
		// идентификатор локализации
		public virtual int LCID { get { return cultureInfo.LCID; } }

		///////////////////////////////////////////////////////////////////////
		// Интерактивная парольная аутентификация
		///////////////////////////////////////////////////////////////////////
		public virtual IAuthentication PasswordAuthentication(IntPtr hwnd)
		{
			return new Authentication(Win32Window.FromHandle(hwnd));
		}
		///////////////////////////////////////////////////////////////////////
		// Сгенерировать случайные данные
		///////////////////////////////////////////////////////////////////////
		[ComVisible(false)]
		public virtual void GenerateRandom(byte[] buffer)
		{
			// создать генератор случайных данных
			using (IRand rand = environment.CreateRand(null))
			{
				// сгенерировать случайные данные
				rand.Generate(buffer, 0, buffer.Length);
			}
		}
		public virtual string GenerateRandom(int cb)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// сгенерировать случайные данные
				byte[] buffer = new byte[cb]; GenerateRandom(buffer);

				// закодировать данные
				return Convert.ToBase64String(buffer); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; }
		}
		///////////////////////////////////////////////////////////////////////
		// Шифрование данных на пароле
		///////////////////////////////////////////////////////////////////////
		/* TODO To be deleted */
		public virtual string PasswordEncrypt(string cultureOID, string password, string data)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// раскодировать данные
				byte[] decoded = Convert.FromBase64String(data);

				// указать тип данных
				CMSData cmsData = new CMSData(ASN1.ISO.PKCS.PKCS7.OID.data, decoded);

				// указать генератор случайных данных
				using (IRand rand = environment.CreateRand(null))
				{
					// указать общие параметры
					PBE.PBECulture culturePBE = environment.GetCulture(null, cultureOID);

					// получить параметры алгоритма наследования ключа
					ASN1.ISO.AlgorithmIdentifier[] keyDeriveAlgorithms =
						new ASN1.ISO.AlgorithmIdentifier[] { culturePBE.KDFAlgorithm(rand) };

					// указать общие параметры
					Culture culture = environment.Factory.GetCulture((SecurityStore)null, cultureOID);

					// получить параметры алгоритма шифрования
					ASN1.ISO.AlgorithmIdentifier cipherAlgorithm = culture.CipherAlgorithm(rand);

					// проверить указание параметров
					if (cipherAlgorithm == null) throw new NotSupportedException();

					// получить алгоритм шифрования ключа
					ASN1.ISO.AlgorithmIdentifier keyWrapAlgorithm = new ASN1.ISO.AlgorithmIdentifier(
						new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS9.OID.smime_pwri_kek),
						cipherAlgorithm
					);
					// получить параметры алгоритма шифрования ключа
					ASN1.ISO.AlgorithmIdentifier[] keyWrapAlgorithms =
						new ASN1.ISO.AlgorithmIdentifier[] { keyWrapAlgorithm };

					// закодировать пароль 
					using (ISecretKey key = SecretKey.FromPassword(password, Encoding.UTF8))
					{
						// зашифровать данные
						ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = CMS.PasswordEncryptData(
							environment.Factory, null, rand, new ISecretKey[] { key }, 
							cipherAlgorithm, keyDeriveAlgorithms, keyWrapAlgorithms, cmsData, null
						);
						// вернуть закодированную структуру
						ASN1.ISO.PKCS.ContentInfo contentInfo = new ASN1.ISO.PKCS.ContentInfo(
							new ASN1.ObjectIdentifier(ASN1.ISO.PKCS.PKCS7.OID.envelopedData), envelopedData
						);
						// вернуть зашифрованные данные
						return Convert.ToBase64String(contentInfo.Encoded);
					}
				}
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; }
		}
		public virtual string PasswordDecrypt(string password, string data)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// раскодировать данные
				byte[] decoded = Convert.FromBase64String(data);

				// раскодировать данные
				ASN1.ISO.PKCS.ContentInfo contentInfo = new ASN1.ISO.PKCS.ContentInfo(
					ASN1.Encodable.Decode(decoded, 0, decoded.Length)
				);
				// закодировать пароль 
				using (ISecretKey key = SecretKey.FromPassword(password, Encoding.UTF8))
				{
					// расшифровать данные на пароле
					CMSData cmsData = CMS.PasswordDecryptData(
						environment.Factory, null, key, contentInfo
					);
					// вернуть расшифрованные данные
					return Convert.ToBase64String(cmsData.Content);
				}
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; }
		}
		///////////////////////////////////////////////////////////////////////
		// Кодирование сертификата и личного ключа
		///////////////////////////////////////////////////////////////////////
		public virtual ICertificate DecodeCertificate(string encoded)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try { 
				// раскодировать сертификат
				CAPI.Certificate certificate = new CAPI.Certificate(
				    Convert.FromBase64String(encoded)
				);
                // создать объект сертификата
                return new Certificate(environment, cultureInfo, certificate); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		public virtual IPrivateKey DecodePrivateKey(string encoded)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try { 
				// извлечь отдельные части
				string[] parts = encoded.Split(','); string provider = parts[0]; 

				// определить область видимости
				Scope scope = (Scope)Enum.Parse(typeof(Scope), parts[1]); 

                // раскодировать имя контейнера
                SecurityInfo info = new SecurityInfo(scope, parts[2]); 

			    // раскодировать сертификат ключа
			    CAPI.Certificate certificate = new CAPI.Certificate(
                    Convert.FromBase64String(parts[3])
                );
                // создать объект личного ключа
                return new PrivateKey(environment, cultureInfo, provider, info, certificate); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		public virtual IPrivateKey DecodePKCS12(string encoded, string password)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture;

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			
			// указать начальные условия
			string providerName = null; CAPI.Certificate certificate = null; 
			try {
				// указать имя контейнера
				SecurityInfo info = new SecurityInfo(Scope.System, "MEMORY", encoded);

				// создать провайдер PKCS12
				using (PKCS12.CryptoProvider provider = environment.CreatePKCS12Provider())
				{
					// указать имя провайдера
					providerName = provider.Name; 

					// раскодировать содержимое контейнера
					using (MemoryStream stream = new MemoryStream(Convert.FromBase64String(encoded)))
					{
						// открыть хранилище контейнеров
						using (Container container = provider.OpenMemoryContainer(stream, FileAccess.Read, password))
						{
							// для всех ключей
							foreach (byte[] keyID in container.GetKeyIDs())
							{
								// получить сертификат
								certificate = container.GetCertificate(keyID); if (certificate != null) break;
							}
						}
					}
					// проверить наличие сертификата
					if (certificate == null) throw new NotFoundException();
				}
				// создать объект личного ключа
				using (PrivateKey privateKey = new PrivateKey(environment, cultureInfo, providerName, info, certificate))
				{ 
					// указать пароль контейнера
					privateKey.Password = password; privateKey.AddRef(); return privateKey; 
				}
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; }
		}
		///////////////////////////////////////////////////////////////////////
		// Перечисление личных ключей
		///////////////////////////////////////////////////////////////////////
		public virtual IPrivateKey SelectPrivateKeySSL(IntPtr hwnd)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
                // указать функцию фильтра
                Predicate<ContainerKeyPair> keyFilter = delegate(ContainerKeyPair keyPair)
                {
                    // проверить наличие сертификата
                    if (keyPair.Certificate == null) return false; 

                    // создать объект сертификата
                    using (Certificate certificate = new Certificate(
                        environment, cultureInfo, keyPair.Certificate))
                    {
						// получить способ использования сертификата
						KeyUsage keyUsage = certificate.KeyUsage;

						// проверить способ использования сертификата
						return (keyUsage & (KeyUsage.KeyEncipherment | KeyUsage.KeyAgreement)) != KeyUsage.None; 
                    }
                };
		        // функция проверки допустимости контейнера
		        GUI.KeyPairsDialog.Callback callback = delegate(
                    Form form, CryptoProvider provider, ContainerKeyPair keyPair)
                {
                    // создать объект личного ключа
                    return new PrivateKey(environment, cultureInfo, 
                        provider.Name, keyPair.Info, keyPair.Certificate
                    ); 
                }; 
				// указать используемое окно
				IWin32Window window = Win32Window.FromHandle(hwnd); 

		        // выбрать контейнер из списка
		        return (PrivateKey)GUI.KeyPairsDialog.Show(window, environment, keyFilter, callback); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		public virtual String[] EnumeratePrivateKeys(IntPtr hwnd, KeyUsage keyUsage, bool system)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 

			// определить область видимости
			Scope scope = system ? Scope.System : Scope.Any; 

			// указать способ аутентификации по умолчанию
			AuthenticationSelector selector = new GUI.AuthenticationSelector(
				Win32Window.FromHandle(hwnd), "USER"
			); 
            try { 
				// создать список описания личных ключей
				List<String> encodedPrivateKeys = new List<String>(); 

                // перечислить фабрики алгоритмов
                using (Factories factories = environment.EnumerateFactories())
                {
			        // для всех провайдеров
			        foreach (CryptoProvider provider in factories.ProviderGroups)
			        {
				        // для всех контейнеров
				        foreach (SecurityInfo info in provider.EnumerateAllObjects(scope))
				        try {
							// получить интерфейс клиента
							using (ClientContainer container = new ClientContainer(provider, info, selector))
							{ 
								// для всех пар ключей контейнера
								foreach (ContainerKeyPair keyPair in container.EnumerateKeyPairs())
								{
									// проверить наличие сертификата
									if (keyPair.Certificate == null) continue; 

									// получить способ использования ключа
									CAPI.KeyUsage usage = keyPair.Certificate.KeyUsage; 

									// проверить способ использования ключа
									if (((int)usage & (int)keyUsage) != (int)keyUsage) continue; 

									// создать объект сертификата
									using (Certificate certificate = new Certificate(
										environment, cultureInfo, keyPair.Certificate))
									{ 
										// закодировать сертификат
										string encodedCertificate = certificate.Encoded; 

										// закодировать личный ключ
										string encodedPrivateKey = String.Format("{0},{1},{2},{3}", 
											provider.Name, info.Scope, info.FullName, encodedCertificate
										); 
										// добавить описание ключа в список
										encodedPrivateKeys.Add(encodedPrivateKey); 
									}
								}
							}
					    } catch {}
                    }
				}
				return encodedPrivateKeys.ToArray(); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		///////////////////////////////////////////////////////////////////////
		// Найти сертификат для проверки подписи
		///////////////////////////////////////////////////////////////////////
		public virtual ICertificate FindVerifyCertificate(string data, string[] encodedCertificates)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try { 
				// выделить память для сертификатов
				List<CAPI.Certificate> certificates = new List<CAPI.Certificate>(); 

				// для всех личных ключей
				for (int i = 0; i < encodedCertificates.Length; i++)
				try {
			        // раскодировать сертификат ключа
			        certificates.Add(new CAPI.Certificate(
						Convert.FromBase64String(encodedCertificates[i])
					));
                }
                // обработать возможную ошибку
                catch { certificates.Add(null); } 
                
				// раскодировать данные
                byte[] decoded = Convert.FromBase64String(data); 

				// интерпретировать данные в формате ContentInfo
				ASN1.ISO.PKCS.ContentInfo contentInfo = 
					new ASN1.ISO.PKCS.ContentInfo(ASN1.Encodable.Decode(decoded));

				// проверить тип данных
				if (contentInfo.ContentType.Value != ASN1.ISO.PKCS.PKCS7.OID.signedData)
				{
					// при ошибке выбросить исключение
					throw new InvalidDataException();
				}
				// интерпретировать данные в формате SignedData
				ASN1.ISO.PKCS.PKCS7.SignedData signedData = 
					new ASN1.ISO.PKCS.PKCS7.SignedData(contentInfo.Inner);

				// найти сертификат для данных
				CAPI.Certificate certificate = CMS.FindCertificate(certificates, signedData); 

                // проверить наличие сертификата
                if (certificate == null) return null;

				// вернуть найденный сертификат
				return new Certificate(environment, cultureInfo, certificate); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		///////////////////////////////////////////////////////////////////////
		// Найти ключ, требуемый для расшифрования/проверки подписи
		///////////////////////////////////////////////////////////////////////
		public virtual IPrivateKey FindDecryptPrivateKey(string data, string[] encodedPrivateKeys)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try { 
				// выделить память для сертификатов
				List<CAPI.Certificate> certificates = new List<CAPI.Certificate>(); 

				// для всех личных ключей
				for (int i = 0; i < encodedPrivateKeys.Length; i++)
				try {
				    // извлечь отдельные части
				    string[] parts = encodedPrivateKeys[i].Split(','); 

			        // раскодировать сертификат ключа
			        certificates.Add(new CAPI.Certificate(Convert.FromBase64String(parts[3])));
                }
                // обработать возможную ошибку
                catch { certificates.Add(null); } 
                
				// раскодировать данные
                byte[] decoded = Convert.FromBase64String(data); 

				// интерпретировать данные в формате ContentInfo
				ASN1.ISO.PKCS.ContentInfo contentInfo = 
					new ASN1.ISO.PKCS.ContentInfo(ASN1.Encodable.Decode(decoded));

				// проверить тип данных
				if (contentInfo.ContentType.Value != ASN1.ISO.PKCS.PKCS7.OID.envelopedData)
				{
					// при ошибке выбросить исключение
					throw new InvalidDataException();
				}
				// раскодировать данные
				ASN1.ISO.PKCS.PKCS7.EnvelopedData envelopedData = 
					new ASN1.ISO.PKCS.PKCS7.EnvelopedData(contentInfo.Inner); 

				// найти сертификат для данных
				CAPI.Certificate certificate = CMS.FindCertificate(certificates, envelopedData); 

                // проверить наличие сертификата
                if (certificate == null) return null; int index =  certificates.IndexOf(certificate);

                // раскодировать личный ключ
                return DecodePrivateKey(encodedPrivateKeys[index]); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
	}
}
