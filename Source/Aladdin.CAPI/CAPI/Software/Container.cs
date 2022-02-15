using System; 

namespace Aladdin.CAPI.Software
{
	///////////////////////////////////////////////////////////////////////////
	// Программный контейнер
	///////////////////////////////////////////////////////////////////////////
	public abstract class Container : CAPI.Container
	{
        // поток вывода
        private ContainerStream stream; 

		// открыть существующий контейнер
		protected Container(ContainerStore store, ContainerStream stream)
            
            // сохранить переданные параметры
            : base(store, stream.Name) { this.stream = RefObject.AddRef(stream); } 

        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(stream); base.OnDispose();
        }
        // уникальный идентификатор
        public override string GetUniqueID() { return stream.UniqueID; }

        ///////////////////////////////////////////////////////////////////////
        // Поддержка аутентификации
        ///////////////////////////////////////////////////////////////////////
        public override Type[] GetAuthenticationTypes(string user) 
        { 
            // указать поддерживаемую аутентификацию
            return new Type[] { typeof(Auth.PasswordCredentials) }; 
        } 
		public string Password { set 
        {
            // установить тип аутентификации
            CAPI.Authentication authentication = 
                new Auth.PasswordCredentials("USER", value); 

            // выполнить аутентификацию
            Authentication = authentication; Authenticate(); 
        }}
        ///////////////////////////////////////////////////////////////////////
		// содержимое контейнера
		public abstract byte[] Encoded { get; }  

		// сохранить пару ключей для алгоритма
		public override byte[] SetKeyPair(IRand rand, 
            KeyPair keyPair, KeyUsage keyUsage, KeyFlags keyFlags) 
        { 
            // сохранить данные контейнера
            Flush(); return keyPair.KeyID; 
        }
		// удалить пару ключей для алгоритма
		public override void DeleteKeyPair(byte[] keyID) { Flush(); }

        // сохранить данные контейнера
        public void Flush() { stream.Write(Encoded); }
	}
}
