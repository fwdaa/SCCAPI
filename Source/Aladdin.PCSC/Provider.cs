using System;
using System.Collections.Generic;

namespace Aladdin.PCSC
{
	///////////////////////////////////////////////////////////////////////
	// Смарт-карточная подсистема
	///////////////////////////////////////////////////////////////////////
	public class Provider
	{
        // конструктор
        public Provider(Module module) { this.module = module; } 

        // используемый модуль
        public Module Module { get { return module; }} private Module module;

		// создать обобщенную группу считывателей
		public ReaderGroup GetReaderGroup(string[] groups)
        {
		    // создать обобщенную группу считывателей
            return new ReaderGroup(module, ReaderScope.Reserved, groups); 
        }
		// создать обобщенную группу считывателей
		public ReaderGroup GetReaderGroup(ReaderScope scope, string[] groups)
        {
		    // создать обобщенную группу считывателей
            return new ReaderGroup(module, scope, groups); 
        }
		// перечислить группы считывателей
		public string[] EnumerateReaderGroups()
        {
            // создать используемый контекст
            ulong hContext = module.EstablishContext(ReaderScope.User); 
            try {
	            // перечислить группы считывателей
	            return module.ListReaderGroups(hContext); 
            }
            // освободить контекст
            finally { module.ReleaseContext(hContext); }
        }
		// перечислить группы считывателей
		public string[] EnumerateReaderGroups(ReaderScope scope)
        {
	        // создать список системных групп
	        List<String> systemGroups = new List<String>(); 

            // создать используемый контекст
            ulong hSysContext = module.EstablishContext(ReaderScope.System); 
            try {
	            // перечислить группы считывателей
	            string[] groups = module.ListReaderGroups(hSysContext); 

	            // вернуть системные группы считывателей
	            if (scope == ReaderScope.System) return groups; 

                // добавить системные группы в список
                systemGroups.AddRange(groups); 
            }
            // освободить контекст
            finally { module.ReleaseContext(hSysContext); }

	        // создать пустой список групп
	        List<String> userGroups = new List<String>(); 

            // создать используемый контекст
            ulong hUserContext = module.EstablishContext(ReaderScope.User); 
            try {
	            // перечислить группы считывателей
	            foreach (string group in module.ListReaderGroups(hUserContext))
                {
		            // проверить отсутствие системной группы
		            if (!systemGroups.Contains(group)) userGroups.Add(group); 
                }
                return userGroups.ToArray(); 
            }
            // освободить контекст
            finally { module.ReleaseContext(hUserContext); } 
        }
        // перечислить считыватели
        public Reader[] EnumerateReaders()
        {
            // получить обобщенную группу считывателей
            ReaderGroup readerGroup = GetReaderGroup(null); 
            
            // перечислить считыватели
            return readerGroup.EnumerateReaders(); 
        }
        // перечислить считыватели
        public Reader[] EnumerateReaders(ReaderScope scope)
        {
            // получить обобщенную группу считывателей
            ReaderGroup readerGroup = GetReaderGroup(scope, null); 
            
            // перечислить считыватели
            return readerGroup.EnumerateReaders(); 
        }
		// получить описание считывателя
		public Reader GetReader(ReaderScope scope, string name) 
        { 
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

		    // получить описание считывателя
            return new Reader(module, scope, name); 
        }
        public Remoting.RemoteClientControl StartListener(
            IReaderHandler readerHandler, Remoting.IBackgroundHandler handler)
        {
            // указать обобщенную группу считывателей
            ReaderGroup readerGroup = GetReaderGroup(null); 

            // запустить прослушиватель событий считывателей
            return readerGroup.StartListener(readerHandler, handler); 
        }
        // запустить прослушиватель событий считывателей
        public Remoting.RemoteClientControl StartListener(
            ReaderScope scope, IReaderHandler readerHandler, Remoting.IBackgroundHandler handler)
        {
            // указать обобщенную группу считывателей
            ReaderGroup readerGroup = GetReaderGroup(scope, null); 

            // запустить прослушиватель событий считывателей
            return readerGroup.StartListener(readerHandler, handler); 
        }
	}
}
