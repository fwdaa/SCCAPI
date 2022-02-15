using System;
using System.Collections.Generic;
using System.Reflection;
using System.IO;
using System.Diagnostics.CodeAnalysis; 
using Aladdin.PCSC; 

namespace Aladdin.CAPI.SCard.Windows
{
    ///////////////////////////////////////////////////////////////////////////
    // Провайдер апплетов
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class Provider : CAPI.Provider
    {
        // смарт-карточная подсистема и провайдер апплетов
        private PCSC.Provider cardSystem; private IProviderImpl impl; 

		// конструктор
		public Provider() 
		{
            // получить смарт-карточную подсистему
            cardSystem = PCSC.Windows.Provider.Instance; string name = "Aladdin.CAPI.SCard.APDU";

            // указать имя типа для загрузки
            string typeName = String.Format("{0}.ProviderImpl", name); 

            // получить описание типа
            Type type = Type.GetType(typeName, false); if (type == null) 
            { 
                // получить выполняемую сборку
                Assembly executingAssembly = Assembly.GetExecutingAssembly(); 

                // определить путь выполняемой сборки
                string path = Path.GetDirectoryName(executingAssembly.Location); 
            
                // при наличии локальной сборки
                if (File.Exists(path = String.Format("{0}\\{1}.dll", path, name)))
                {
                   // получить информацию класса
                    type = Assembly.LoadFile(path).GetType(typeName, true); 
                }
                else { 
                    // определить токен открытого ключа
                    byte[] publicKeyToken = executingAssembly.GetName().GetPublicKeyToken(); 

                    // создать имя загружаемой сборки
                    AssemblyName assemblyName = new AssemblyName(); assemblyName.Name = name; 

                    // указать номер версии сборки
                    assemblyName.Version = executingAssembly.GetName().Version; 

                    // указать локализацию сборки
                    assemblyName.CultureInfo = executingAssembly.GetName().CultureInfo; 

                    // указать токен открытого ключа
                    assemblyName.SetPublicKeyToken(publicKeyToken); 

                    // указать полное имя типа
                    typeName = String.Format("{0},{1}", typeName, assemblyName.FullName); 

                    // получить информацию класса
                    type = Type.GetType(typeName, true); 
                }
            }
            // получить описание конструктора
            ConstructorInfo info = type.GetConstructor(Type.EmptyTypes); 

            // вызвать конструктор
            try { impl = (IProviderImpl)info.Invoke(null); }

            // обработать возможное исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
		}
        // имя провайдера
        public override string Name { get { return impl.Name; }}

		///////////////////////////////////////////////////////////////////////
		// Управление хранилищами провайдера
		///////////////////////////////////////////////////////////////////////
		public override string[] EnumerateStores(Scope scope)
        {
            // создать список смарт-карт
            List<String> stores = new List<String>(); Reader[] readers = null; 

            // перечислить считыватели
            if (scope == Scope.Any) readers = cardSystem.EnumerateReaders(); 
            else { 
                // указать область видимости
                ReaderScope readerScope = (scope == Scope.System) ? ReaderScope.System : ReaderScope.User; 

                // перечислить считыватели
                readers = cardSystem.EnumerateReaders(readerScope); 
            }
            // для всех считывателей
            foreach (Reader reader in readers)
            try {
                // добавить имя считывателя в список
                if (reader.GetState() == ReaderState.Card) stores.Add(reader.Name); 
            }
            // вернуть список смарт-карт
            catch {} return stores.ToArray(); 
        } 
        public override SecurityStore OpenStore(Scope scope, string storeName) 
        { 
            // указать область видимости
            ReaderScope readerScope = (scope == Scope.System) ? ReaderScope.System : ReaderScope.User; 
            
            // получить описание считывателя
            Reader reader = cardSystem.GetReader(readerScope, storeName); 
            
            // проверить наличие смарт-карты
            PCSC.Card card = (PCSC.Card)reader.OpenCard();
             
            // при ошибке выбросить исключение
            if (card == null) throw new NotFoundException(); 
            
            // вернуть объект хранилища            
            return new Card(this, impl, scope, card); 
        }     
    }
}
