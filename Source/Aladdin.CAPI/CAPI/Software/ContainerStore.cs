using System;
using System.IO;

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище программных контейнеров
	///////////////////////////////////////////////////////////////////////////
	public abstract class ContainerStore : CAPI.ContainerStore
	{
		// конструктор
		public ContainerStore(CryptoProvider provider, Scope scope) : base(provider, scope) {}
		// конструктор
		public ContainerStore(SecurityStore parent) : base(parent) {}

        // используемый провайдер
        public new CryptoProvider Provider { get { return (CryptoProvider)base.Provider; }}

		///////////////////////////////////////////////////////////////////////
		// Поддержка аутентификации
		///////////////////////////////////////////////////////////////////////
        public override Type[] GetChildAuthenticationTypes(string user) 
        { 
            // указать поддерживаемую аутентификацию
            return new Type[] { typeof(Auth.PasswordCredentials) }; 
        } 
		///////////////////////////////////////////////////////////////////////
		// Управление контейнерами
		///////////////////////////////////////////////////////////////////////
		// создать контейнер
		public override SecurityObject CreateObject(IRand rand, 
            object name, object authenticationData, params object[] parameters)
        {
		    // проверить наличие пароля 
		    if (authenticationData == null) throw new ArgumentException();
        
            // выполнить преобразование типа
            String password = (String)authenticationData; 
            try { 
                // создать контейнер
                using (ContainerStream stream = CreateStream(name))  
                {
                    // создать контейнер
                    Container container = Provider.CreateContainer(
                        rand, this, stream, password, (string)parameters[0]
                    );
                    // записать содержимое контейнера
                    stream.Write(container.Encoded); return container;  
                }
            }
            // обработать возможную ошибку
            catch { DeleteStream(name); throw; }
        }
		// открыть контейнер
		public override SecurityObject OpenObject(object name, FileAccess access)
		{
            // открыть контейнер
            using (ContainerStream stream = OpenStream(name, access))
            { 
                // вернуть контейнер
                return Provider.OpenContainer(this, stream);
            }
		}
		// удалить контейнер
        public override void DeleteObject(object name, Authentication[] authentications) 
        { 
		    // удалить контейнер
            DeleteStream(name); base.DeleteObject(name, authentications); 
        }
		///////////////////////////////////////////////////////////////////////
		// Управление физическими потоками
		///////////////////////////////////////////////////////////////////////

        // создать поток
        protected abstract ContainerStream CreateStream(object name); 
        
        // открыть поток
        protected abstract ContainerStream OpenStream(object name, FileAccess access); 
        
        // удалить поток
        protected abstract void DeleteStream(object name);
    }
}
