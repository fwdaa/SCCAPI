using System;
using System.IO;
using System.Globalization;
using System.Threading;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

namespace Aladdin.CAPI.COM
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ
	///////////////////////////////////////////////////////////////////////////
    [ClassInterface(ClassInterfaceType.None)]
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class PrivateKey : RefObject, IPrivateKey
	{
		private CryptoEnvironment		environment;	// среда окружения
		private CultureInfo				cultureInfo;	// локализация
		private CryptoProvider			provider;		// криптопровайдер
		private SecurityInfo			containerInfo;	// информация контейнера
        private CAPI.Certificate		certificate;    // сертификат ключа
		private Authentication			authentication; // способ аутентификации

		// конструктор
		public PrivateKey(CryptoEnvironment environment, CultureInfo cultureInfo, 
			string providerName, SecurityInfo info, CAPI.Certificate certificate) 
		{
            // сохранить переданные параметры
			this.environment = RefObject.AddRef(environment); authentication = null; 

			// сохранить переданные параметры
			this.cultureInfo = cultureInfo; this.certificate = certificate; 

            // перечислить фабрики алгоритмов
            using (Factories factories = environment.EnumerateFactories())
            {
			    // для всех провайдеров
                foreach (CryptoProvider provider in factories.Providers)
			    {
				    // проверить совпадение имени провайдера
				    if (provider.Name != providerName) continue;
 
                    // сохранить используемый провайдер
                    this.provider = RefObject.AddRef(provider); 
					
                    // указать используемый контейнер
					this.containerInfo = info; return; 
                }
            }
			// при ошибке выбросить исключение
			throw new NotFoundException();
		}
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(provider); RefObject.Release(environment); base.OnDispose(); 
        }
		// получить строковое представление
		public override string ToString() 
		{ 
			// закодировать сертификат
			string encodedCertificate = Convert.ToBase64String(certificate.Encoded); 

			// вернуть строковое представление
			return String.Format("{0},{1},{2},{3}", provider.Name, 
                containerInfo.Scope, containerInfo.FullName, encodedCertificate
            ); 
		}
		///////////////////////////////////////////////////////////////////////
		// Указать способ аутентификации
		///////////////////////////////////////////////////////////////////////
		public virtual IAuthentication Authentication { set {

			// указать способ выбора аутентификации
			authentication = (Authentication)value; 
        }}
		// указать пароль контейнера
		public virtual string Password { set
		{
			// указать способ выбора аутентификации
			authentication = new Authentication(value); 
		}}
		///////////////////////////////////////////////////////////////////////
		// получить сертификат контейнера
		///////////////////////////////////////////////////////////////////////
		public virtual ICertificate Certificate { get 
		{	
            // создать объект сертификата
            return new Certificate(environment, cultureInfo, certificate); 
		}}
		// связать контекст сертификата с ключом
		public virtual void SetCertificateContext(IntPtr pCertificateContext)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// указать способ аутентификации по умолчанию
				AuthenticationSelector selector = new AuthenticationSelector("USER"); 

				// указать способ аутентификации
				if (authentication != null) selector = authentication.Selector; 

				// открыть контейнер
				using (Container containerObject = (Container)selector.OpenObject(
					provider, containerInfo.Scope, containerInfo.FullName, FileAccess.Read))
				{ 
					// определить тип контейнера
					Type containerType = containerObject.GetType();

					// получить описание метода
					MethodInfo method = containerType.GetMethod("SetCertificateContext");

					// проверить наличие метода
					if (method == null) throw new InvalidOperationException(); 

					// вызвать метод
					try { method.Invoke(containerObject, new object[] { pCertificateContext }); }

					// обработать возможное исключение
					catch (TargetInvocationException e) { throw e.InnerException; }
				}
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; }
		}
		///////////////////////////////////////////////////////////////////////
		// Зашифровать данные на сертификате
		///////////////////////////////////////////////////////////////////////
		public virtual string Encrypt(ICertificate recipientCertificate, string data)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// раскодировать данные
				byte[] decoded = Convert.FromBase64String(data);

				// зашифровать данные на открытом ключе
				byte[] encrypted = Encrypt(recipientCertificate, decoded);

				// закодировать данные
				return Convert.ToBase64String(encrypted); 
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		[ComVisible(false)] 
		public byte[] Encrypt(ICertificate recipientCertificate, byte[] data)
		{
			// указать способ аутентификации по умолчанию
			AuthenticationSelector selector = new AuthenticationSelector("USER"); 

			// указать способ аутентификации
			if (authentication != null) selector = authentication.Selector; 

	        // получить интерфейс клиента
	        using (ClientContainer client = new ClientContainer(provider, containerInfo, selector))
	        { 
                // создать список сертификатов
                CAPI.Certificate[] recipientCertificates = new CAPI.Certificate[] { 
                    new CAPI.Certificate(Convert.FromBase64String(recipientCertificate.Encoded))
                }; 
                // указать тип данных
                CMSData cmsData = new CMSData(ASN1.ISO.PKCS.PKCS7.OID.data, data); 

				// создать генератор случайных данных
				using (IRand rand = client.CreateRand())
				{ 
					// зашифровать данные на открытом ключе
					return client.EncryptData(rand, certificate, recipientCertificates, cmsData, null); 
				}
            }
        }
		///////////////////////////////////////////////////////////////////////
		// расшифровать данные с использованием контейнера
		///////////////////////////////////////////////////////////////////////
		public virtual string Decrypt(string data)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// раскодировать данные
				byte[] decoded = Convert.FromBase64String(data);

				// расшифровать данные
				byte[] decrypted = Decrypt(decoded);

				// закодировать данные
				return Convert.ToBase64String(decrypted);
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}		
		[ComVisible(false)]
		public byte[] Decrypt(byte[] contentInfo)
		{
			// указать способ аутентификации по умолчанию
			AuthenticationSelector selector = new AuthenticationSelector("USER"); 

			// указать способ аутентификации
			if (authentication != null) selector = authentication.Selector; 

	        // получить интерфейс клиента
	        using (ClientContainer client = new ClientContainer(provider, containerInfo, selector))
			{ 
				// расшифровать данные
			    return client.DecryptData(contentInfo).Content;
            }
		}
		///////////////////////////////////////////////////////////////////////
		// подписать данные на личном ключе
		///////////////////////////////////////////////////////////////////////
		public virtual string SignData(string data)
		{
			// сохранить установленную культуру
			CultureInfo cultureThread = Thread.CurrentThread.CurrentUICulture; 

			// установить культуру
			Thread.CurrentThread.CurrentUICulture = cultureInfo; 
			try {
				// раскодировать данные
				byte[] decoded = Convert.FromBase64String(data);

				// подписать данные
				byte[] signed = SignData(decoded);

				// закодировать данные
				return Convert.ToBase64String(signed);
			}
			// восстановить культуру
			finally { Thread.CurrentThread.CurrentUICulture = cultureThread; } 
		}
		[ComVisible(false)]
		public byte[] SignData(byte[] data)
		{
			// указать способ аутентификации по умолчанию
			AuthenticationSelector selector = new AuthenticationSelector("USER"); 

			// указать способ аутентификации
			if (authentication != null) selector = authentication.Selector; 

	        // получить интерфейс клиента
	        using (ClientContainer client = new ClientContainer(provider, containerInfo, selector))
			{ 
                // указать тип данных
                CMSData cmsData = new CMSData(ASN1.ISO.PKCS.PKCS7.OID.data, data); 

				// создать генератор случайных данных
				using (IRand rand = client.CreateRand())
				{ 
					// подписать данные
					return client.SignData(rand, certificate, cmsData, null, null);
				}
            }
		}
	}
}
