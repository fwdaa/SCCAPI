using System;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Зашифрованный на открытом ключ контейнер PKCS12 с имитовставкой
	///////////////////////////////////////////////////////////////////////////
	public class PfxAuthenticatedEnvelopedContainer : PfxEnvelopedContainer, IPfxAuthenticatedContainer
	{
        // фабрика алгоритмов и пароль проверки целостности
        private Factory factory; private string password;

		// конструктор
		public PfxAuthenticatedEnvelopedContainer(ASN1.ISO.PKCS.PKCS12.PFX content, 
			Factory factory, IRand rand) : base(content, rand)
        { 
            // сохранить переданные параметры
            this.factory = RefObject.AddRef(factory); password = null; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
		    RefObject.Release(factory); base.OnDispose();
        }
        // фабрика алгоритмов
        public Factory Factory { get { return factory; }}
        // пароль проверки целостности
        public string AuthenticationPassword { get { return password; }}

		// указать пароль проверки целостности
		public void SetAuthenticationPassword(string password)
		{
			// проверить целостность контейнера
			Pfx.CheckAuthenticatedContainer(Factory, content, password); 
			
			// сохранить переданный пароль
			this.password = password;  
		}
        // изменить пароль проверки целостности
		public void ChangeAuthenticationPassword(string password)
		{
            // проверить наличие пароля
            if (this.password == null) throw new UnauthorizedAccessException(); 

			// сохранить переданный пароль
			string oldPassword = this.password; this.password = password; 

            // обработать изменение данных
            try { Change(); } catch { this.password = oldPassword; throw; }
		}
		protected override void OnChange(ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe authenticatedSafe)
		{
			// проверить наличие пароля
			if (password == null) throw new UnauthorizedAccessException();

			// выделить память для salt-значения
			byte[] salt = new byte[content.MacData.MacSalt.Value.Length]; 

			// сгенерировать salt-значение
			Rand.Generate(salt, 0, salt.Length); 

			// получить число итераций
			int iterations = content.MacData.Iterations.Value.IntValue; 

			// вычислить имитовставку от контейнера
			content = Pfx.CreateAuthenticatedContainer(Factory, authenticatedSafe, 
				content.MacData.Mac.DigestAlgorithm, salt, iterations, password
			); 
		}
	}
}
