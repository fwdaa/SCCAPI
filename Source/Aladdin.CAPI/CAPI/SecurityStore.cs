using System;
using System.Collections.Generic;
using System.IO;

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище защищенных объектов
	///////////////////////////////////////////////////////////////////////////
    public abstract class SecurityStore : SecurityObject
    {
        // криптографический провайдер и область видимости
        private IProvider provider; private Scope scope;

        // конструктор
		public SecurityStore(IProvider provider, Scope scope) : base(null) 
        { 
            // сохранить переданные параметры
            this.provider = RefObject.AddRef(provider); this.scope = scope; 
        } 
        // конструктор
		public SecurityStore(SecurityStore parent) : base(parent) 
        { 
            // сохранить переданные параметры
            this.provider = RefObject.AddRef(parent.Provider); this.scope = parent.Scope; 
        } 
        // освободить выделенные ресурсы
        protected override void OnDispose()
        {
            // освободить выделенные ресурсы
            RefObject.Release(provider); base.OnDispose();
        }
        // провайдер объекта
        public override IProvider Provider { get { return provider; }} 
        // область видимости
        public Scope Scope { get { return scope; }}

        // информация объекта
        public override SecurityInfo Info { get { 

            // информация объекта
            if (Store != null) return base.Info; 

            // информация объекта
            return new SecurityInfo(scope, null, Name); 
        }}
        // уникальный идентификатор
        public virtual String GetUniqueID() { return Info.FullName; }

		///////////////////////////////////////////////////////////////////////
        // Поддержка аутентификации
		///////////////////////////////////////////////////////////////////////

        // аутентификация создаваемых дочерних объектов
        public virtual Type[] GetChildAuthenticationTypes(string user) 
        { 
            return new Type[0]; 
        } 
		///////////////////////////////////////////////////////////////////////
        // Управление только внутренними объектами
		///////////////////////////////////////////////////////////////////////

        // выполнить разбор имени
        public virtual string[] ParseObjectName(string fullName)
        {
            // найти первый разделитель
            int index = fullName.IndexOf('\\'); if (index >= 0)
            {
                // извлечь имя хранилища
                string storeName = fullName.Substring(0, index); 

                // извлечь имя объекта
                string name = fullName.Substring(index + 1); 

                // вернуть разобранное имя
                return new string[] { storeName, name }; 
            }
            // вернуть разобранное имя
            else return new string[] { fullName }; 
        }
        // перечислить объекты
		public virtual string[] EnumerateObjects() { return new string[0]; }  

		// создать объект
		public virtual SecurityObject CreateObject(IRand rand, 
            object name, object authenticationData, params object[] parameters)
        {
            // операция не поддерживается
            throw new InvalidOperationException(); 
        }
		// открыть объект
		public abstract SecurityObject OpenObject(object name, FileAccess access);

        // удалить объект
		public virtual void DeleteObject(object name, Authentication[] authentications)
        {
            // удалить объект из кэша аутентификации
            ExecutionContext.GetProviderCache(Provider.Name).ClearData(Info);
        }
		///////////////////////////////////////////////////////////////////////
        // Иерархическое перечисление объектов
		///////////////////////////////////////////////////////////////////////
		public virtual SecurityInfo[] EnumerateAllObjects()
        {
            // создать список описаний объектов
            List<SecurityInfo> infos = new List<SecurityInfo>(); 

            // для всех объектов
            foreach (string name in EnumerateObjects())
            try {
                // открыть объект
                using (SecurityObject obj = OpenObject(name, FileAccess.Read))
                {
                    // для хранилища
                    if (obj is SecurityStore)
                    {
                        // перечислить объекты
                        infos.AddRange(((SecurityStore)obj).EnumerateAllObjects()); 
                    }
                    else { 
                        // добавить описание объекта
                        infos.Add(new SecurityInfo(Scope, FullName, name)); 
                    }
                }
            }
            catch {} return infos.ToArray(); 
        }
    }        
}
