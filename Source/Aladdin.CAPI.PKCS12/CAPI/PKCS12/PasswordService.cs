using System;
using System.Text;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Сервис аутентификации
	///////////////////////////////////////////////////////////////////////////
    public class PasswordService : Auth.PasswordService
    {
        // содержимое контейнера
        private PfxEncryptedContainer container; 

        // конструктор
        public PasswordService(Container obj, PfxEncryptedContainer container) 
            
            // сохранить переданные параметры
            : base(obj, "USER") { this.container = container; } 

        // возможность изменения 
        public override bool CanChange { get { return true; }}

        // информация аутентификации объекта
        public override AuthenticationInfo GetAuthenticationInfo()
        {
            // информация аутентификации объекта
            return new AuthenticationInfo(AuthenticationInfo.UnlimitedAttempts); 
        }
        // указать пароль контейнера
        protected override void SetPassword(string password)
        {
            // проверить тип контейнера
            if (container is PfxAuthenticatedEncryptedContainer)
            {
                // выполнить преобразование типа
                PfxAuthenticatedEncryptedContainer obj = 
                    (PfxAuthenticatedEncryptedContainer)container; 

                // указать пароль контейнера
                obj.SetPassword(password); 
            }
            else { 
                // указать используемый ключ
                ISecretKey key = SecretKey.FromPassword(password, Encoding.UTF8); 

                // расшифровать контейнер
                container.SetEncryptionKey(key); 
            }
        }
        // изменить пароль контейнера
        protected override void ChangePassword(string password)
        {
            // выполнить аутентификацию
            ((Container)Target).Authenticate(); 

            // проверить тип контейнера
            if (container is PfxAuthenticatedEncryptedContainer)
            {
                // выполнить преобразование типа
                PfxAuthenticatedEncryptedContainer obj = 
                    (PfxAuthenticatedEncryptedContainer)container; 

                // изменить пароль
                obj.ChangePassword(password); 
            }
            else { 
                // указать используемый ключ
                ISecretKey key = SecretKey.FromPassword(password, Encoding.UTF8); 

                // переустановить ключ
                container.ChangeEncryptionKey(key); 
            }
            // перезаписать контейнер на диске
            ((Container)Target).Flush(); 
        }
    }
}
