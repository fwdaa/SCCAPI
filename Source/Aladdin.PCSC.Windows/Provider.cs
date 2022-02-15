using System;
using System.Collections.Generic;

namespace Aladdin.PCSC.Windows
{
	///////////////////////////////////////////////////////////////////////
	// Смарт-карточная подсистема Windows
	///////////////////////////////////////////////////////////////////////
    public class Provider : PCSC.Provider
    {
        // cмарт-карточная подсистема Windows
        public static readonly Provider Instance = new Provider(); 

        // конструктор
        public Provider() : base(new Module()) {}

        // используемый модуль
        protected new Module Module { get { return (Module)base.Module; }} 

        ///////////////////////////////////////////////////////////////////
        // Управление группами считывателй
        ///////////////////////////////////////////////////////////////////

        // добавить группу считывателей
        public void AddReaderGroup(ReaderScope scope, string group)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // добавить группу считывателей
                Module.AddReaderGroup(hContext, group); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        // удалить группу считывателей
        public void RemoveReaderGroup(ReaderScope scope, string group)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // удалить группу считывателей
                Module.AddReaderGroup(hContext, group); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        // добавить считыватель в группу
        public void AddReaderToGroup(ReaderScope scope, string reader, string group)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // добавить считыватель в группу
                Module.AddReaderToGroup(hContext, reader, group); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        // удалить считыватель из группы
        public void RemoveReaderFromGroup(ReaderScope scope, string reader, string group)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // удалить считыватель из группы
                Module.RemoveReaderFromGroup(hContext, reader, group); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        ///////////////////////////////////////////////////////////////////
        // Перечисление считывателей
        ///////////////////////////////////////////////////////////////////

        // добавить считыватель (в группу по умолчанию)
        public void AddReader(ReaderScope scope, string reader, string device)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // добавить считыватель (в группу по умолчанию)
                Module.AddReader(hContext, reader, device); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        // удалить считыватель
        public void RemoveReader(ReaderScope scope, string reader)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // удалить считыватель
                Module.RemoveReader(hContext, reader); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        ///////////////////////////////////////////////////////////////////
        // Перечисление типов смарт-карт
        ///////////////////////////////////////////////////////////////////

        // уникальный идентификатор смарт-карты
        public String GetCardUniqueID(ReaderScope scope, string readerName)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // указать используемый считыватель
	        Reader reader = GetReader(scope, readerName);  
            
	        // открыть смарт-карту
	        Card card = (Card)reader.OpenCard(); string uniqueID = readerName;
                
            // перечислить типы смарт-карт
            CardType[] cardTypes = EnumerateCardTypes(scope, card.ATR, null); 

            // при наличии модели
            if (!String.IsNullOrEmpty(card.Model)) { uniqueID = card.Model;
             
                // добавить тип смарт-карты
                if (cardTypes.Length > 0) uniqueID = String.Format("{0}\\{1}", uniqueID, cardTypes[0].Name);  
            }
            // указать тип смарт-карты
            else if (cardTypes.Length > 0) uniqueID = cardTypes[0].Name;  
            
            // при наличии имени производителя
            if (!String.IsNullOrEmpty(card.Manufacturer))
            {
                // добавить имя производителя
                uniqueID = String.Format("{0}\\{1}", card.Manufacturer, uniqueID); 
            }
            // при наличии серийного номера
            if (card.Serial != null && card.Serial.Length > 0)
            {
                // отформатировать серийный номер
                string strSerial = Arrays.ToHexString(card.Serial);

                // добавить серийный номер к идентификатору
                uniqueID = String.Format("{0}\\{1}", uniqueID, strSerial); 
            }
            return uniqueID; 
        }
        // перечислить типы смарт-карт
        public CardType[] EnumerateCardTypes(byte[] atr, Guid[] interfaces)
        {
            // создать список типов смарт-карт
            List<CardType> cardTypes = new List<CardType>(); 

	        // создать список системных типов смарт-карт
	        List<String> sysCardNames = new List<String>(); 

            // создать используемый контекст
            ulong hSysContext = Module.EstablishContext(ReaderScope.System); 
            try {
                // перечислить типы смарт-карт
                sysCardNames.AddRange(Module.ListCardTypes(hSysContext, atr, interfaces)); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hSysContext); } 

	        // создать используемый контекст
	        ulong hUserContext = Module.EstablishContext(ReaderScope.User); 
            try {
                // для всех типов смарт-карт
                foreach (string cardName in Module.ListCardTypes(hUserContext, atr, interfaces))
                {
	                // проверить принадлежность системной области
	                ReaderScope readerScope = sysCardNames.Contains(cardName) ? ReaderScope.System : ReaderScope.User; 

                    // добавить объект типа смарт-карты
                    cardTypes.Add(new CardType(Module, readerScope, cardName)); 
                }
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hUserContext); } return cardTypes.ToArray();
        }
        // перечислить типы смарт-карт
        public CardType[] EnumerateCardTypes(ReaderScope scope, byte[] atr, Guid[] interfaces)
        {
            // создать список типов смарт-карт
            List<CardType> cardTypes = new List<CardType>(); 

	        // создать список системных типов смарт-карт
	        List<String> sysCardNames = new List<String>(); 

            // создать используемый контекст
            ulong hSysContext = Module.EstablishContext(ReaderScope.System); 
            try {
                // перечислить типы смарт-карт
                sysCardNames.AddRange(Module.ListCardTypes(hSysContext, atr, interfaces)); 

                // для системной области видимости
                if (scope == ReaderScope.System)
                { 
                    // для всех типов смарт-карт
                    for (int i = 0; i < sysCardNames.Count; i++)
                    {
                        // добавить объект типа смарт-карты
                        cardTypes.Add(new CardType(Module, scope, sysCardNames[i])); 
                    }
                    return cardTypes.ToArray();
                }
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hSysContext); } 

	        // создать используемый контекст
	        ulong hUserContext = Module.EstablishContext(ReaderScope.User); 
            try {
                // для всех типов смарт-карт
                foreach (string cardName in Module.ListCardTypes(hUserContext, atr, interfaces))
                {
	                // проверить принадлежность системной области
                    if (sysCardNames.Contains(cardName)) continue; 

                    // добавить объект типа смарт-карты
                    cardTypes.Add(new CardType(Module, scope, cardName)); 
                }
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hUserContext); } return cardTypes.ToArray();
        }
        // добавить тип смарт-карт
        public CardType AddCardType(ReaderScope scope, string cardName, 
            MaskATR maskATR, Guid primaryProvider, Guid[] interfaces)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // добавить тип смарт-карт
                Module.AddCardType(hContext, cardName, 
                    maskATR.Value, maskATR.Mask, primaryProvider, interfaces
                ); 
                // вернуть объект типа смарт-карты
                return new CardType(Module, scope, cardName); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        // удалить тип смарт-карт
        public void RemoveCardType(ReaderScope scope, string cardName)
        {
		    // проверить корректность параметров
		    if (scope == ReaderScope.Reserved) throw new ArgumentException(); 

	        // создать используемый контекст
	        ulong hContext = Module.EstablishContext(scope); 
            try {
                // удалить тип смарт-карт
                Module.RemoveCardType(hContext, cardName); 
            }
            // освободить выделенные ресурсы
            finally { Module.ReleaseContext(hContext); } 
        }
        ///////////////////////////////////////////////////////////////////
	    // Выбрать логический считыватель
        ///////////////////////////////////////////////////////////////////
        private class FILTER_PROC_ARGS { 
            public Module       module;         // используемый модуль
	        public ReaderScope  scope;		    // область видимости
	        public ReaderFilter filter;		    // функция-фильтр пользователя 
            public List<String> sysNames;       // имена системных считывателей
	        public object       userData;	    // дополнительные данные
        };
        private static bool FilterProc(ulong hContext, ulong hCard, object userData)
        {
	        // преобразовать тип параметров
	        FILTER_PROC_ARGS args = (FILTER_PROC_ARGS)userData; 

            // проверить указание функции-фильтра
            if (args.filter == null) return true; ReaderScope scope = ReaderScope.User; 
            try {
                // получить информацию считывателя
                ReaderStatus readerStatus = args.module.GetReaderStatus(hCard); 

                // указать имя считывателя по умолчанию
                string readerName = readerStatus.readers[0]; 

	            // указать область видимости
	            if (args.scope == ReaderScope.System) scope = args.scope; 
	            else {
	                // для всех полученных имен
	                for (int i = 0; i < readerStatus.readers.Length; i++)
	                {
		                // проверить принадлежность системной области
		                if (!args.sysNames.Contains(readerStatus.readers[i])) continue; 

                        // проверить совпадение области видимости
                        if (args.scope == ReaderScope.User) return false; 

                        // указать область видимости и имя считывателя
                        scope = ReaderScope.System; readerName = readerStatus.readers[i]; break; 
                    }
                }
                // создать объект считывателя
                Reader reader = new Reader(args.module, scope, readerName); 
                
                // создать объект сеанса
                using (ReaderSession session = new ReaderSession(
                    args.module, hContext, hCard, readerStatus.protocol))
                {
                    // вызвать функцию фильтра
                    return args.filter(reader, session, args.userData); 
                }
            }
            // вернуть результат
            catch {} return false; 
        }
	    public Reader SelectReader(string[] groups, string[] cardNames, Guid[] interfaces, 
            ReaderFilter filter, OpenMode openMode, Protocol protocols, 
            SelectMode selectMode, SelectParams selectParams, object userData)
        {
            // выделить память для параметров функции
            FILTER_PROC_ARGS parameters = new FILTER_PROC_ARGS(); 
            
            // сохранить режим открытия и предпочтительные протоколы
            parameters.module = Module; parameters.scope = ReaderScope.Reserved; 

            // сохранить функцию фильтра и дополнительные данные
            parameters.filter = filter; parameters.userData = userData; parameters.sysNames = null;

            // указать системный контекст
            ulong hSysContext = Module.EstablishContext(ReaderScope.System); 
            try {
                // перечислить системные считыватели
                parameters.sysNames = new List<String>(Module.ListReaders(hSysContext, groups)); 
            }
            // освободить системный контекст
            finally { Module.ReleaseContext(hSysContext); }
            
            // указать используемый контекст
            ulong hContext = Module.EstablishContext(ReaderScope.User); 
            try {
	            // выбрать логический считыватель
                string readerName = Module.SelectReader(hContext, 
                    groups, cardNames, interfaces, FilterProc, 
                    openMode, protocols, selectMode, selectParams, parameters
                );
                // проверить выбор считывателя
                if (readerName == null) return null; 

                // проверить принадлежность системной области
                if (parameters.sysNames.Contains(readerName))
                {
                    // создать объект считывателя
                    return new Reader(Module, ReaderScope.System, readerName); 
                }
                else {
                    // создать объект считывателя
                    return new Reader(Module, ReaderScope.User, readerName); 
                }
            }
            // освободить используемый контекст
            finally { Module.ReleaseContext(hContext); }
        }
	    public Reader SelectReader(ReaderScope scope, 
            string[] groups, string[] cardNames, Guid[] interfaces, 
            ReaderFilter filter, OpenMode openMode, Protocol protocols, 
            SelectMode selectMode, SelectParams selectParams, object userData)
        {
            // выделить память для параметров функции
            FILTER_PROC_ARGS parameters = new FILTER_PROC_ARGS(); 
            
            // сохранить режим открытия и предпочтительные протоколы
            parameters.module = Module; parameters.scope = scope; 

            // сохранить функцию фильтра и дополнительные данные
            parameters.filter = filter; parameters.userData = userData; 

            // при необходимости перечисления системных считывателей
            parameters.sysNames = null; if (scope != ReaderScope.System) 
            { 
                // указать системный контекст
		        ulong hSysContext = Module.EstablishContext(ReaderScope.System); 
                try {
                    // перечислить системные считыватели
                    parameters.sysNames = new List<String>(Module.ListReaders(hSysContext, groups)); 
                }
                // освободить системный контекст
                finally { Module.ReleaseContext(hSysContext); }
            }
            // указать используемый контекст
            ulong hContext = Module.EstablishContext(scope); 
            try {
	            // выбрать логический считыватель
                string readerName = Module.SelectReader(hContext, 
                    groups, cardNames, interfaces, FilterProc, 
                    openMode, protocols, selectMode, selectParams, parameters
                );
                // проверить выбор считывателя
                if (readerName == null) return null;
                
                // создать объект считывателя
                return new Reader(Module, scope, readerName); 
            }
            // освободить используемый контекст
            finally { Module.ReleaseContext(hContext); }
        }
    }
}
