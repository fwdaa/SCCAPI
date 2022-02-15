using System; 
using System.Collections.Generic; 

namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Группа считывателей
    ///////////////////////////////////////////////////////////////////////////
    public sealed class ReaderGroup
    {
		// модуль, область видимости и группы считывателей
		private Module module; private ReaderScope scope; private string[] groups;	

        // конструктор
        internal ReaderGroup(Module module, ReaderScope scope, string[] groups)
        {
            // проверить указание групп
            if (groups == null) groups = new string[] { "SCard$AllReaders" }; 

            // сохранить переданные параметры
            this.module = module; this.scope = scope; this.groups = groups; 
        }
        // запустить прослушиватель событий считывателя
        public Remoting.RemoteClientControl StartListener(
            IReaderHandler readerHandler, Remoting.IBackgroundHandler handler)
        {
		    // указать функцию удаленного потока
		    using (ReaderListener client = new ReaderListener(module, scope, groups, readerHandler))
            { 
		        // запустить поток
		        return client.Start(handler); 
            }
        }
        // перечислить считыватели
        public Reader[] EnumerateReaders()
        {
            // создать системный контекст
            ulong hSysContext = module.EstablishContext(ReaderScope.System); 
            try {
                // перечислить системные считыватели
                if (scope == ReaderScope.System) return EnumerateReaders(hSysContext, hSysContext);

                // создать пользовательский контекст
                ulong hUserContext = module.EstablishContext(ReaderScope.User); 
                try {
                    // перечислить считыватели
                    return EnumerateReaders(hUserContext, hSysContext); 
                }
                // освободить контекст
                finally { module.ReleaseContext(hUserContext); } 
            }
            // освободить контекст
            finally { module.ReleaseContext(hSysContext); }
        }
        // перечислить считыватели
        private Reader[] EnumerateReaders(ulong hContext, ulong hSysContext)
        {
	        // создать список считывателей
	        List<Reader> readers = new List<Reader>();

	        // перечислить системные считыватели
	        List<String> sysNames = new List<String>(module.ListReaders(hSysContext, groups));

            // при перечислении системных считывателей
            if (scope == ReaderScope.System) for (int i = 0; i < sysNames.Count; i++)
	        {
		        // создать описание считывателя
		        readers.Add(new Reader(module, scope, sysNames[i])); 
	        }
            else { 
	            // перечислить пользовательские считыватели
	            string[] userNames = module.ListReaders(hContext, groups);

                // для каждого считывателя
	            for (int i = 0; i < userNames.Length; i++)
	            {
	                // проверить принадлежность системной области
	                ReaderScope readerScope = sysNames.Contains(userNames[i]) ? ReaderScope.System : ReaderScope.User; 

	                // проверить область видимости
	                if (scope == ReaderScope.Reserved || readerScope == ReaderScope.User)
	                { 
		                // создать объект считывателя
		                readers.Add(new Reader(module, readerScope, userNames[i])); 
	                }
                }
	        }
            return readers.ToArray();
        }
        ///////////////////////////////////////////////////////////////////////
        // Обработчик событий считывателей
        ///////////////////////////////////////////////////////////////////////
        public class Handler : Module.IReaderHandler
        {
            // группа считывателей и список известных считывателей
            private ReaderGroup readerGroup; private List<Reader> knownReaders;
            // обработчик событий считывателей и системный контекст
            private IReaderHandler readerHandler; private ulong hSysContext; 
        
            // конструктор
            public Handler(ReaderGroup readerGroup, IReaderHandler readerHandler, ulong hSysContext)
            {
                // создать список известных считывателей
                this.readerGroup = readerGroup; knownReaders = new List<Reader>();
            
                // сохранить переданные параметры
                this.readerHandler = readerHandler; this.hSysContext = hSysContext; 
            }
            // перечислить считыватели
            public string[] ListReaders(ulong hContext) 
            {
                // заново перечислить считыватели
                Reader[] readers = readerGroup.EnumerateReaders(hContext, hSysContext); 

                // создать список имен считывателей
                string[] names = new string[readers.Length]; 

                // для всех считывателей
                for (int i = 0; i < readers.Length; i++) 
                {
                    // найти объект считывателя
                    Reader reader = FindReader(readers[i].Name); 
                    
                    // добавить информацию считывателя
                    if (reader == null) knownReaders.Add(readers[i]); 

                    // указать имя считывателя
                    names[i] = readers[i].Name; 
                }
                return names; 
            }
            // создать объект считывателя
            protected Reader FindReader(string readerName)
            {
                // для всех считывателей из списка
                foreach (Reader reader in knownReaders)
                {
                    // проверить совпадение имени
                    if (reader.Name == readerName) return reader; 
                }
                return null; 
            }
            // добавление считывателя
            public void OnInsertReader(ulong hContext, string readerName) 
            {
                // получить объект считывателя
                Reader reader = FindReader(readerName); 
                
                // вызвать функцию обработки
                if (reader != null) readerHandler.OnInsertReader(reader);
            }
            // удаление считывателя
            public void OnRemoveReader(ulong hContext, string readerName) 
            {
                // получить объект считывателя
                Reader reader = FindReader(readerName); 
                
                // вызвать функцию обработки
                if (reader != null) readerHandler.OnRemoveReader(reader);
            }
            // добавление смарт-карты
            public void OnInsertCard(ulong hContext, string readerName)
            {
                // получить объект считывателя
                Reader reader = FindReader(readerName); 
                
                // вызвать функцию обработки
                if (reader != null) readerHandler.OnInsertCard(reader);
            }
            // удаление смарт-карты
            public void OnRemoveCard(ulong hContext, string readerName) 
            {
                // получить объект считывателя
                Reader reader = FindReader(readerName); 
                
                // вызвать функцию обработки
                if (reader != null) readerHandler.OnRemoveCard(reader);
            }
        }
    }
}
