using System;
using System.Security;
using System.Runtime.InteropServices;

///////////////////////////////////////////////////////////////////////////////
// Определение базовых типов
///////////////////////////////////////////////////////////////////////////////
using LONG         = System.Int32; 
using DWORD        = System.UInt32; 
using SCARDCONTEXT = System.UIntPtr; 
using SCARDHANDLE  = System.UIntPtr; 

namespace Aladdin.PCSC
{
    internal class NativeMethods
    {
        ///////////////////////////////////////////////////////////////////////
        // Используемые структуры
        ///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SCARD_READERSTATE {
            public String      szReader;       // имя считывателя
            public IntPtr      pvUserData;     // данные пользователя
            public DWORD       dwCurrentState; // текущее состояние считывателя
            public DWORD       dwEventState;   // состояние считывателя после изменения
            public LONG        cbAtr;          // размер ATR в байтах
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)]
            public Byte[]      rgbAtr;         // ATR вставленной карты
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SCARD_IO_REQUEST {
	        public DWORD       dwProtocol;	    // идентификатор протокола
	        public LONG        cbPciLength;	    // размер данных протокола
        }
        ///////////////////////////////////////////////////////////////////////
        // Контекст диспетчера смарт-карт
        ///////////////////////////////////////////////////////////////////////

        // создать контекст
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardEstablishContext(
            [In     ] DWORD                 dwScope, 
            [In     ] IntPtr                pvReserved1, 
            [In     ] IntPtr                pvReserved2, 
            [    Out] out SCARDCONTEXT      phContext
        );
        // закрыть контекст
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardReleaseContext(
            [In     ] SCARDCONTEXT          hContext
        );
        // закрыть контекст
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardFreeMemory(
            [In     ] SCARDCONTEXT          hContext, 
            [In     ] IntPtr                pvMem
        );
        ///////////////////////////////////////////////////////////////////////
        // Управление группами считывателй
        ///////////////////////////////////////////////////////////////////////

        // перечислить группы считывателей
        [DllImport("winscard.dll", EntryPoint = "SCardListReaderGroupsW", 
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardListReaderGroups(
            [In     ] SCARDCONTEXT          hContext,
            [    Out] out IntPtr            mszGroups, 
            [In, Out] ref LONG              pcchGroups 
        );
        // добавить группу считывателей /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardIntroduceReaderGroupW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardIntroduceReaderGroup(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szGroupName 
        );
        // удалить группу считывателей /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardForgetReaderGroupW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardForgetReaderGroup(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szGroupName 
        );
        // добавить считыватель в группу /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardAddReaderToGroupW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardAddReaderToGroup(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szReaderName,  
            [In     ] String                szGroupName  
        );
        // удалить считыватель из группы /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardRemoveReaderFromGroupW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardRemoveReaderFromGroup(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szReaderName,  
            [In     ] String                szGroupName  
        );
        ///////////////////////////////////////////////////////////////////////
        // Перечисление считывателей
        ///////////////////////////////////////////////////////////////////////

        // перечислить считыватели
        [DllImport("winscard.dll", EntryPoint = "SCardListReadersW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardListReaders(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                mszGroups, 
            [    Out] out IntPtr            mszReaders, 
            [In, Out] ref LONG              pcchReaders 
        );
        // добавить считыватель (в группу по умолчанию) /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardIntroduceReaderW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardIntroduceReader(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szReaderName, 
            [In     ] String                szDeviceName 
        );
        // удалить считыватель /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardForgetReaderW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardForgetReader(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szReaderName 
        );
        // дождаться события смарт-карт
        [DllImport("winscard.dll", EntryPoint = "SCardGetStatusChangeW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardGetStatusChange(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] DWORD                 dwTimeout,
            [In, Out] SCARD_READERSTATE[]   rgReaderStates,
            [In     ] LONG                  cReaders
        );
        // найти смарт-карты в считывателях /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardLocateCardsW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardLocateCards(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                mszCards,
            [In, Out] SCARD_READERSTATE[]   rgReaderStates,
            [In     ] LONG                  cReaders
        );
        // отменить ожидание события смарт-карт
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardCancel(
            [In     ] SCARDCONTEXT          hContext
        ); 

        ///////////////////////////////////////////////////////////////////////
        // Перечисление типов смарт-карт
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_PROVIDER_PRIMARY            = 1;
        public const uint SCARD_PROVIDER_CSP                = 2;
        public const uint SCARD_PROVIDER_KSP                = 3;

        // перечислить типы смарт-карт /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardListCardsW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardListCardTypes(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] Byte[]                pbAtr, 
            [In     ] Guid[]                rgguidInterfaces, 
            [In     ] LONG                  cguidInterfaceCount,
            [    Out] out IntPtr            mszCards, 
            [In, Out] ref LONG              pcchCards 
        );
        // добавить тип смарт-карт /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardIntroduceCardTypeW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardIntroduceCardType(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szCardName,
            [In     ] Guid[]                pguidPrimaryProvider,
            [In     ] Guid[]                rgguidInterfaces,
            [In     ] LONG                  dwInterfaceCount,
            [In     ] Byte[]                pbAtr, 
            [In     ] Byte[]                pbAtrMask, 
            [In     ] LONG                  cbAtrLen
        ); 
        // удалить тип смарт-карт /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardForgetCardTypeW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardForgetCardType(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szCardName
        ); 

        // получить идентификатор первичного провайдера /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardGetProviderIdW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardGetProviderId(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szCard,
            [    Out] out Guid              pguidProviderId 
        );
        // перечислить интерфейсы смарт-карт /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardListInterfacesW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardListInterfaces(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szCard,
            [In, Out] Guid[]                pguidInterfaces, 
            [In, Out] ref LONG              pcguidInterfaces 
        );
        // получить имя провайдера /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardGetCardTypeProviderNameW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardGetCardTypeProviderName(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szCardName,
            [In     ] DWORD                 dwProviderId,
            [    Out] out IntPtr            szProvider, 
            [In, Out] ref LONG              pcchProvider 
        );
        // установить имя провайдера /* Windows */
        [DllImport("winscard.dll", EntryPoint = "SCardSetCardTypeProviderNameW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardSetCardTypeProviderName(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szCardName,
            [In     ] DWORD                 dwProviderId,
            [In     ] String                szProvider 
        );
        ///////////////////////////////////////////////////////////////////////
        // Управление считывателями и смарт-картами
        ///////////////////////////////////////////////////////////////////////

        // открыть смарт-карту
        [DllImport("winscard.dll", EntryPoint = "SCardConnectW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardConnect(
            [In     ] SCARDCONTEXT          hContext,
            [In     ] String                szReader,
            [In     ] DWORD                 dwShareMode,
            [In     ] DWORD                 dwPreferredProtocols,
            [    Out] out SCARDHANDLE       phCard,
            [    Out] out DWORD             pdwActiveProtocol
        );
        // заново открыть смарт-карту
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardReconnect(
            [In     ] SCARDHANDLE           hCard,
            [In     ] DWORD                 dwShareMode,
            [In     ] DWORD                 dwPreferredProtocols,
            [In     ] DWORD                 dwInitialization,
            [    Out] out DWORD             pdwActiveProtocol
        );
        // закрыть смарт-карту
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardDisconnect( 
            [In     ] SCARDHANDLE           hCard,
            [In     ] DWORD                 dwDisposition
        );
        // получить состояние смарт-карты
        [DllImport("winscard.dll", EntryPoint = "SCardStatusW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardStatus(
            [In     ] SCARDHANDLE           hCard,
            [In     ] IntPtr                mszReaderNames, 
            [In, Out] ref LONG              pcchReaderLen, 
            [    Out] out DWORD             pdwState, 
            [    Out] out DWORD             pdwProtocol, 
            [In, Out] Byte[]                pbAtr, 
            [In, Out] ref LONG              pcbAtrLen
        ); 
        // получить атрибут считывателя
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardGetAttrib(
            [In     ] SCARDHANDLE           hCard,
            [In     ] DWORD                 dwAttrId,
            [In, Out] Byte[]                pbAttr,
            [In, Out] ref LONG              pcbAttrLen
        );
        // установить атрибут считывателя
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardSetAttrib(
            [In     ] SCARDHANDLE           hCard,
            [In     ] DWORD                 dwAttrId,
            [In     ] Byte[]                pbAttr,
            [In     ] LONG                  cbAttrLen
        );
        // передать команду считывателю
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardControl(
            [In     ] SCARDHANDLE           hCard, 
            [In     ] DWORD                 dwControlCode,
            [In     ] Byte[]                lpInBuffer,
            [In     ] LONG                  cbInBufferSize, 
            [In, Out] Byte[]                lpOutBuffer, 
            [In     ] LONG                  cbOutBufferSize, 
            [    Out] out LONG              lpBytesReturned
        ); 
        // начать транзакцию со смарт-картой
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardBeginTransaction(
            [In     ] SCARDHANDLE           hCard
        ); 
        // завершить транзакцию со смарт-картой
        [DllImport("winscard.dll", ExactSpelling = true)]
        public static extern DWORD SCardEndTransaction(
            [In     ] SCARDHANDLE           hCard, 
            [In     ] DWORD                 dwDisposition
        ); 
        // передать команду смарт-карте
        [DllImport("winscard.dll", ExactSpelling = true, 
            CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardTransmit(
            [In     ] SCARDHANDLE           hCard, 
            [In     ] ref SCARD_IO_REQUEST  pioSendPci,
            [In     ] Byte[]                pbSendBuffer,
            [In     ] LONG                  cbSendLength,
            [In, Out] ref SCARD_IO_REQUEST  pioRecvPci,
            [In, Out] Byte[]                pbRecvBuffer,
            [In, Out] ref LONG              pcbRecvLength
        );
        ///////////////////////////////////////////////////////////////////////
        // Выбор считывателя/смарт-карты
        ///////////////////////////////////////////////////////////////////////
        public const uint SC_DLG_MINIMAL_UI         = 0x01;
        public const uint SC_DLG_NO_UI              = 0x02;
        public const uint SC_DLG_FORCE_UI           = 0x04;

        // Функция-фильтр считывателей
        public delegate bool ReaderFilter(ulong hContext, ulong hCard, object userData);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        public delegate SCARDHANDLE CONNPROC(
            [In     ] SCARDCONTEXT              hContext, 
            [In     ] String                    szReader, 
            [In     ] IntPtr                    mszCards, 
            [In     ] IntPtr                    pvUserData
        );
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate void DSCPROC(
            [In     ] SCARDCONTEXT              hContext, 
            [In     ] SCARDHANDLE               hCard, 
            [In     ] IntPtr                    pvUserData
        );
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        public delegate int CHKPROC(
            [In     ] SCARDCONTEXT              hContext, 
            [In     ] SCARDHANDLE               hCard, 
            [In     ] IntPtr                    pvUserData
        );
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OPENCARD_SEARCH_CRITERIA {
            public LONG                         dwStructSize;
            public String                       lpstrGroupNames; 
            public LONG                         nMaxGroupNames; 
            [MarshalAs(UnmanagedType.LPArray)]
            public Guid[]                       rgguidInterfaces;       
            public LONG                         cguidInterfaces; 
            public String                       lpstrCardNames; 
            public LONG                         nMaxCardNames; 
            public CHKPROC                      lpfnCheck;              
            public CONNPROC                     lpfnConnect;            
            public DSCPROC                      lpfnDisconnect;         
            public IntPtr                       pvUserData;             
            public DWORD                        dwShareMode;            
            public DWORD                        dwPreferredProtocols;   
        };
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct OPENCARDNAME : IDisposable 
        {
            public LONG                         dwStructSize;           
            public SCARDCONTEXT                 hSCardContext;          
            public IntPtr                       hwndOwner;              
            public DWORD                        dwFlags;                
            public String                       lpstrTitle;             
            public String                       lpstrSearchDesc;        
            public IntPtr                       hIcon;
            [MarshalAs(UnmanagedType.LPArray)]
            public OPENCARD_SEARCH_CRITERIA[]   pOpenCardSearchCriteria;
            public CONNPROC                     lpfnConnect;            
            public IntPtr                       pvUserData;             
            public DWORD                        dwShareMode;            
            public DWORD                        dwPreferredProtocols;   
            public IntPtr                       lpstrRdr;
            public LONG                         nMaxRdr;
            public IntPtr                       lpstrCard;
            public LONG                         nMaxCard;
            public DWORD                        dwActiveProtocol;
            public SCARDHANDLE                  hCardHandle;

            // конструктор
            [SecuritySafeCritical]
            public OPENCARDNAME(OpenMode openMode, Protocol protocols, 
                Windows.SelectMode selectMode, Windows.SelectParams selectParams, 
                int maxReaderLength, int maxCardLength)
            {
	            // указать буферы для имени считывателя и типа смарт-карты
	            this.lpstrRdr  = Marshal.AllocHGlobal(maxReaderLength * 2); 
	            this.lpstrCard = Marshal.AllocHGlobal(maxCardLength   * 2); 
                
                // указать мак
                this.nMaxRdr  = maxReaderLength; this.nMaxCard = maxCardLength;

                // инициализировать переменные
                this.hSCardContext = UIntPtr.Zero; this.pOpenCardSearchCriteria = null; 
                // инициализировать переменные
                this.lpfnConnect = null; this.pvUserData = IntPtr.Zero; 

                // указать режим отображения
                this.dwFlags = NativeMethods.SC_DLG_NO_UI; switch (selectMode)
                {
                // указать режим отображения
                case Windows.SelectMode.Minimal: this.dwFlags = NativeMethods.SC_DLG_MINIMAL_UI; break; 
                case Windows.SelectMode.ForceUI: this.dwFlags = NativeMethods.SC_DLG_FORCE_UI;   break; 
                }
	            // установить родительское окно и иконку
	            this.hwndOwner = (selectParams != null) ? selectParams.HWnd  : IntPtr.Zero; 
                this.hIcon     = (selectParams != null) ? selectParams.HIcon : IntPtr.Zero; 

	            // указать строки заголовка и поиска
	            this.lpstrTitle      = (selectParams != null) ? selectParams.Title  : null; 
                this.lpstrSearchDesc = (selectParams != null) ? selectParams.Search : null; 

                // закодировать режим открытия
                this.dwShareMode = Encoding.EncodeOpenMode(openMode); 

                // закодировать предпочтительные протоколы
                this.dwPreferredProtocols = Encoding.EncodeProtocol(protocols);

                // инициализировать переменные
                this.dwActiveProtocol = API.SCARD_PROTOCOL_UNDEFINED; this.hCardHandle = UIntPtr.Zero;

                // указать размер структуры
                this.dwStructSize = 0; this.dwStructSize = Marshal.SizeOf(this); 
            }
            // освободить выделенные ресурсы
            [SecuritySafeCritical]
            public void Dispose() { Marshal.FreeHGlobal(lpstrRdr); Marshal.FreeHGlobal(lpstrCard); }
        };
        // выбрать считыватель/смарт-карту /* Windows */
        [DllImport("scarddlg.dll", EntryPoint = "SCardUIDlgSelectCardW",
            CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        public static extern DWORD SCardUIDlgSelectCard([In, Out] ref OPENCARDNAME parameters); 
    }
}
