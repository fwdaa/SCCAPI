using System;
using System.Text;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Зашифрованный на пароле контейнер PKCS12 с имитовставкой
	///////////////////////////////////////////////////////////////////////////
	public class PfxAuthenticatedEncryptedContainer : PfxEncryptedContainer, IPfxAuthenticatedContainer
	{
		// конструктор
		public PfxAuthenticatedEncryptedContainer(ASN1.ISO.PKCS.PKCS12.PFX content, 
			Factory factory, IRand rand) 
			
			// сохранить переданные параметры
            : base(content, factory, rand) { password = null; } private string password;

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
		// указать пароль 
		public void SetPassword(string password)
		{
            // создать новый ключ шифрования
            ISecretKey key = SecretKey.FromPassword(password, Encoding.UTF8); 

		    // указать пароль проверки целостности и ключ шифрования
            SetAuthenticationPassword(password); SetEncryptionKey(key);
		}
        // изменить пароль 
		public void ChangePassword(string password)
		{
            // проверить наличие пароля
            if (this.password == null) throw new UnauthorizedAccessException(); 

            // создать новый ключ шифрования
            ISecretKey key = SecretKey.FromPassword(password, Encoding.UTF8); 

            // сохранить старый ключ шифрования
            using (ISecretKey oldKey = RefObject.AddRef(EncryptionKey)) 
            { 
                // изменить ключ шифрования и пароль проверки целостности
                ChangeEncryptionKey(key); try { ChangeAuthenticationPassword(password); }

                // при ошибке восстановить старый ключ шифрования
                catch { ChangeEncryptionKey(oldKey); throw; }
            }
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
