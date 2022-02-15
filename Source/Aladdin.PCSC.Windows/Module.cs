using System;
using System.Security;
using System.Security.Permissions;
using System.Runtime.InteropServices;

namespace Aladdin.PCSC.Windows
{
    ///////////////////////////////////////////////////////////////////////////
    // Реализация интерфейса PC/SC
    ///////////////////////////////////////////////////////////////////////////
    public class Module : ModuleMethods
    {
        ///////////////////////////////////////////////////////////////////////
        // Управление группами считывателй
        ///////////////////////////////////////////////////////////////////////

        // добавить группу считывателей
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void AddReaderGroup(ulong hContext, string group)
        {
            // добавить группу считывателей
            Exception.Check(NativeMethods.SCardIntroduceReaderGroup(
                new UIntPtr(hContext), group
            )); 
        }
        // удалить группу считывателей
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void RemoveReaderGroup(ulong hContext, string group)
        {
            // удалить группу считывателей
            Exception.Check(NativeMethods.SCardForgetReaderGroup(
                new UIntPtr(hContext), group
            )); 
        }
        // добавить считыватель в группу
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void AddReaderToGroup(ulong hContext, string reader, string group)
        {
            // добавить считыватель в группу
            Exception.Check(NativeMethods.SCardAddReaderToGroup(
                new UIntPtr(hContext), reader, group
            )); 
        }
        // удалить считыватель из группы
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void RemoveReaderFromGroup(ulong hContext, string reader, string group)
        {
            // удалить считыватель из группы
            Exception.Check(NativeMethods.SCardRemoveReaderFromGroup(
                new UIntPtr(hContext), reader, group
            )); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Перечисление считывателей
        ///////////////////////////////////////////////////////////////////////

        // добавить считыватель (в группу по умолчанию)
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void AddReader(ulong hContext, string reader, string device)
        {
            // добавить считыватель (в группу по умолчанию)
            Exception.Check(NativeMethods.SCardIntroduceReader(
                new UIntPtr(hContext), reader, device
            )); 
        }
        // удалить считыватель
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void RemoveReader(ulong hContext, string reader)
        {
            // удалить считыватель
            Exception.Check(NativeMethods.SCardForgetReader(
                new UIntPtr(hContext), reader
            )); 
        }
        // найти смарт-карты в считывателях
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        private uint LocateCards(ulong hContext, 
            string[] cardTypes, NativeMethods.SCARD_READERSTATE[] states)
        {
            // закодировать мультистроку
            string multiCards = Encoding.EncodeMultiString(cardTypes); 

            // найти смарт-карты в считывателях
            return NativeMethods.SCardLocateCards(
                new UIntPtr(hContext), multiCards, states, states.Length
            ); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Перечисление типов смарт-карт
        ///////////////////////////////////////////////////////////////////////

        // перечислить типы смарт-карт
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public string[] ListCardTypes(ulong hContext, byte[] atr, Guid[] interfaces)
        {
            // проверить указание интерфейсов
            if (interfaces == null) interfaces = new Guid[0]; 

            // указать признак автоматического выделения памяти
            IntPtr ptr; int cchCards = API.SCARD_AUTOALLOCATE; 

            // перечислить типы смарт-карт
            Exception.Check(NativeMethods.SCardListCardTypes(
                new UIntPtr(hContext), atr, interfaces, 
                interfaces.Length, out ptr, ref cchCards
            )); 
            try {
                // извлечь мультистроку
                string multiString = Marshal.PtrToStringUni(ptr, cchCards); 

                // раскодировать мультистроку
                return Encoding.DecodeMultiString(multiString); 
            }
            // освободить выделенную память
            finally { NativeMethods.SCardFreeMemory(new UIntPtr(hContext), ptr); }
        }
        // добавить тип смарт-карт
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void AddCardType(ulong hContext, string cardName, 
            byte[] atr, byte[] atrMask, Guid primaryProvider, Guid[] interfaces)
        {
            // проверить корректность размера
            if (atr.Length != atrMask.Length) throw new ArgumentException(); 

            // проверить указание интерфейсов
            if (interfaces == null) interfaces = new Guid[0]; 

            // при наличии первичного провайдера
            Guid[] pguidPrimaryProvider = null; if (primaryProvider != Guid.Empty)
            {
                // указать идентификатор первичного провайдера
                pguidPrimaryProvider = new Guid[] { primaryProvider }; 
            }
            // добавить тип смарт-карт
            Exception.Check(NativeMethods.SCardIntroduceCardType(
                new UIntPtr(hContext), cardName, pguidPrimaryProvider, 
                interfaces, interfaces.Length, atr, atrMask, atr.Length
            )); 
        }
        // удалить тип смарт-карт
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void RemoveCardType(ulong hContext, string cardName)
        {
            // удалить тип смарт-карт
            Exception.Check(NativeMethods.SCardForgetCardType(
                new UIntPtr(hContext), cardName
            )); 
        }
        // получить идентификатор первичного провайдера
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public Guid GetCardTypePrimaryProvider(ulong hContext, string cardName)
        {
            // получить идентификатор первичного провайдера
            Guid guidProviderId; uint code = NativeMethods.SCardGetProviderId(
                new UIntPtr(hContext), cardName, out guidProviderId
            ); 
            // проверить код ошибки
            if (code == API.SCARD_E_UNKNOWN_CARD) Exception.Check(code); 

            // вернуть идентификатор первичного провайдера
            return (code == API.SCARD_S_SUCCESS) ? guidProviderId : Guid.Empty; 
        }
        // перечислить интерфейсы смарт-карт
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public Guid[] GetCardTypeInterfaces(ulong hContext, string cardName)
        {
            // определить требуемый размер буфера
            int cguidInterfaces = 0; uint code = NativeMethods.SCardListInterfaces(
                new UIntPtr(hContext), cardName, null, ref cguidInterfaces
            );
            // проверить код ошибки
            if (code == API.SCARD_E_UNKNOWN_CARD) Exception.Check(code); 

            // проверить отсутствие ошибок
            if (code != API.SCARD_S_SUCCESS) return new Guid[0]; 

            // выделить буфер требуемого размера
            Guid[] guidInterfaces = new Guid[cguidInterfaces]; 

            // перечислить интерфейсы смарт-карт
            Exception.Check(NativeMethods.SCardListInterfaces(
                new UIntPtr(hContext), cardName, guidInterfaces, ref cguidInterfaces
            )); 
            // изменить размер буфера
            Array.Resize(ref guidInterfaces, cguidInterfaces); return guidInterfaces; 
        }
        // получить имя провайдера 
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public string GetCardTypeProvider(ulong hContext, string cardName, uint providerId)
        {
            // указать признак автоматического выделения памяти
            IntPtr ptr; int cchProvider = API.SCARD_AUTOALLOCATE; 

            // получить имя провайдера 
            uint code = NativeMethods.SCardGetCardTypeProviderName(
                new UIntPtr(hContext), cardName, providerId, out ptr, ref cchProvider
            ); 
            // проверить код ошибки
            if (code == API.SCARD_E_UNKNOWN_CARD) Exception.Check(code); 

            // проверить отсутствие ошибок
            if (code != API.SCARD_S_SUCCESS) return null; 
            try {
                // извлечь строку
                string name = Marshal.PtrToStringUni(ptr, cchProvider); 

                // удалить завершающий символ
                if (name.EndsWith("\0")) name = name.Substring(0, name.Length - 1); return name; 
            }
            // освободить выделенную память
            finally { NativeMethods.SCardFreeMemory(new UIntPtr(hContext), ptr); }
        }
        // получить имя провайдера 
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public void SetCardTypeProvider(ulong hContext, 
            string cardName, uint providerId, string name)
        {
            // установить имя провайдера 
            Exception.Check(NativeMethods.SCardSetCardTypeProviderName(
                new UIntPtr(hContext), cardName, providerId, name
            )); 
        }
        ///////////////////////////////////////////////////////////////////////
        // Выбор считывателя/смарт-карты
        ///////////////////////////////////////////////////////////////////////
        private class CHECK_PROC_ARGS { 
	        public NativeMethods.ReaderFilter filter;	// функция-фильтр пользователя 
	        public object                     userData;	// дополнительные данные
        };
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        private static int CheckProc(UIntPtr hContext, UIntPtr hCard, IntPtr pvUserData)
        {
	        // преобразовать тип параметров
	        CHECK_PROC_ARGS args = (CHECK_PROC_ARGS)GCHandle.FromIntPtr(pvUserData).Target; 

            // проверить указание функции-фильтра
            if (args.filter == null) return 1; bool code = false; 
            try {
                // вызвать функцию фильтра
                code = args.filter(hContext.ToUInt64(), hCard.ToUInt64(), args.userData); 
            }
            // вернуть результат
            catch {} return (code) ? 1 : 0; 
        }
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
	    internal string SelectReader(ulong hContext, 
            string[] groups, string[] cardNames, Guid[] interfaces, 
		    NativeMethods.ReaderFilter filter, OpenMode openMode, Protocol protocols, 
		    SelectMode selectMode, SelectParams selectParams, object userData)
        {
            // выделить память для параметров функции
            CHECK_PROC_ARGS parameters = new CHECK_PROC_ARGS(); 
            
            // сохранить функцию фильтра и дополнительные данные
            parameters.filter = filter; parameters.userData = userData; 

	        // создать структуру параметров фильтра
	        NativeMethods.OPENCARD_SEARCH_CRITERIA[] criteria = new NativeMethods.OPENCARD_SEARCH_CRITERIA[1]; 
                
            // проверить указание групп считывателей
            if (groups == null) { criteria[0].lpstrGroupNames = null; criteria[0].nMaxGroupNames = 0; }
            else {
                // закодировать группы считывателей
                criteria[0].lpstrGroupNames = Encoding.EncodeMultiString(groups); 

                // указать размер мультистроки
                criteria[0].nMaxGroupNames = criteria[0].lpstrGroupNames.Length; 
            }
            // проверить указание типов смарт-карт
            if (cardNames == null) { criteria[0].lpstrCardNames = null; criteria[0].nMaxCardNames = 0; }
            else {
                // закодировать типы смарт-карт
                criteria[0].lpstrCardNames = Encoding.EncodeMultiString(cardNames); 

                // указать размер мультистроки
                criteria[0].nMaxCardNames = criteria[0].lpstrCardNames.Length; 
            }
            // при отсутствии интерфейсов
            if (interfaces == null || interfaces.Length == 0)
            {
                // указать отсутствие интерфейсов
                criteria[0].rgguidInterfaces = null; criteria[0].cguidInterfaces = 0;
            }
            else {
                // указать требуемые интерфейсы
                criteria[0].rgguidInterfaces = interfaces; 
                criteria[0].cguidInterfaces  = interfaces.Length; 
            }
	        // указать функции открытия и закрытия сеанса
	        criteria[0].lpfnConnect = null; criteria[0].lpfnDisconnect = null; 

	        // указать функции фильтра
            criteria[0].lpfnCheck = CheckProc; criteria[0].pvUserData = IntPtr.Zero; 

            // указать размер структуры
            criteria[0].dwStructSize = 0; criteria[0].dwStructSize = Marshal.SizeOf(criteria); 

	        // создать структуру параметров диалога
	        NativeMethods.OPENCARDNAME info = new NativeMethods.OPENCARDNAME(
                openMode, protocols, selectMode, selectParams, 256, 256
            ); 
            // указать описатель корнтекста и информацию фильтра
            info.hSCardContext = new UIntPtr(hContext); info.pOpenCardSearchCriteria = criteria;
            try { 
	            // заблокировать параметры в памяти
	            GCHandle lockParameters = GCHandle.Alloc(parameters);
                try { 
                    // указать адрес передаваемых данных
                    criteria[0].pvUserData = GCHandle.ToIntPtr(lockParameters); 

                    // выбрать смарт-карту
                    uint code = NativeMethods.SCardUIDlgSelectCard(ref info); 

	                // проверить выбор смарт-карты и отсутствие ошибок
	                if (code == API.SCARD_W_CANCELLED_BY_USER) return null; 
                    
                    // закрыть описатель сеанса
                    NativeMethods.SCardDisconnect(info.hCardHandle, API.SCARD_LEAVE_CARD); 
                    
                    // проверить отсутствие ошибок
                    Exception.Check(code); 
                }
                // отменить блокировку параметров
                finally { lockParameters.Free(); } 

                // извлечь имя считывателя
                return Marshal.PtrToStringUni(info.lpstrRdr); 
            }
            // освободить выделенные ресурсы
            finally { info.Dispose(); }
        }
    }
}
