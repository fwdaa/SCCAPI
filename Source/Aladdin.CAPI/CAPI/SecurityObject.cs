using System;
using System.Collections.Generic;
using System.Security.Authentication;

namespace Aladdin.CAPI
{
 	///////////////////////////////////////////////////////////////////////////
	// Защищенный объект
	///////////////////////////////////////////////////////////////////////////
	public abstract class SecurityObject : MarshalRefObject
    {
        // хранилище защищенных объектов и используемые аутентификации
        private SecurityStore store; private Authentication[] authentications;

        // конструктор
		public SecurityObject(SecurityStore store) 
        { 
            // сохранить переданные параметры
            this.store = RefObject.AddRef(store); 

            // аутентификация отсутствует
            authentications = new Authentication[0]; 
        }
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(store); base.OnDispose();
        }
        ///////////////////////////////////////////////////////////////////////
        // Описание защищенного объекта
        ///////////////////////////////////////////////////////////////////////

        // криптографический провайдер
        public virtual IProvider Provider { get { return store.Provider; }}
        // хранилище объектов
        public SecurityStore Store { get { return store; }}

        // информация объекта
        public virtual SecurityInfo Info { get { 

            // информация объекта
            return new SecurityInfo(store.Scope, store.FullName, Name); 
        }}
        // имя объекта
        public abstract object Name { get; }

        // полное имя объекта
        public string FullName { get { return Info.FullName; }}

        ///////////////////////////////////////////////////////////////////////
        // Настройка аутентификации
        ///////////////////////////////////////////////////////////////////////

        // поддерживаемые типы аутентификации
        public virtual Type[] GetAuthenticationTypes(string user) { return new Type[0]; } 

        // получить сервис аутентификации
        public virtual AuthenticationService GetAuthenticationService(
            string user, Type authenticationType) { return null; } 

		// проверить необходимость аутентификации
        public virtual bool IsAuthenticationRequired(Exception e) 
        { 
		    // проверить необходимость аутентификации
            if (e is UnauthorizedAccessException || e is AuthenticationException) return true; 

            // проверить необходимость аутентификации
            return (store != null) ? store.IsAuthenticationRequired(e) : false; 
        }
        ///////////////////////////////////////////////////////////////////////
        // Аутентификация
        ///////////////////////////////////////////////////////////////////////

        // используемая аутентификация
        public Authentication[] Authentications
        {
            // получить используемые аутентификации
            get { return authentications; }

            // установить используемые аутентификации
            set { authentications = value; 

                // проверить указание аутентификаций
                if (authentications == null) authentications = new Authentication[0]; 
            }
        }
        // установить аутентификацию
        public Authentication Authentication 
        { 
            // сбросить аутентификацию
            set { authentications = new Authentication[0]; 
                
                // установить аутентификацию
                if (value != null) authentications = new Authentication[] { value }; 
            }
        }
		// выполнить аутентификацию
        public bool EnsureAuthenticate()
        {
            // выполнить аутентификацию 
            try { return Authenticate().Length > 0; } catch { return false; }
        }
		// выполнить аутентификацию
		public virtual Credentials[] Authenticate() 
		{
            // список выполненных аутентификаций
            List<Credentials> credentialsList = new List<Credentials>();

            // выполнить аутентификацию родительского каталога
            if (Store != null) credentialsList.AddRange(Store.Authenticate()); 

            // для всех аутентификаций
            for (int i = 0; i < authentications.Length; i++)
            {
                // выполнить аутентификацию через кэш
                Credentials[] credentials = ExecutionContext.CacheAuthenticate(
                    this, authentications[i].User, authentications[i].Types
                ); 
                // явно выполнить аутентификацию
                if (credentials == null) credentials = authentications[i].Authenticate(this);

                // сохранить пройденную аутентификацию
                credentialsList.AddRange(credentials); if (credentials.Length == 1) authentications[i] = credentials[0];
                else { 
                    // определить число оставшихся аутентификаций
                    int remaining = authentications.Length - (i + 1); 

                    // изменить общее число аутентификаций
                    Array.Resize(ref authentications, authentications.Length + credentials.Length - 1); 

                    // скопировать непройденные аутентификации
                    Array.Copy(authentications, i + 1, authentications, i + credentials.Length, remaining); 

                    // для всех пройденных аутентификаций
                    for (int j = 0; j < credentials.Length; j++)
                    { 
                        // скопировать пройденную аутентификацию
                        authentications[i + j] = credentials[j]; 
                    }
                }
            }
            // вернуть пройденные аутентификации
            return credentialsList.ToArray();  
		}
    }
}
 