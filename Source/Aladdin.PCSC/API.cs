namespace Aladdin.PCSC
{
    ///////////////////////////////////////////////////////////////////////////
    // Интерфейс PC/SC
    ///////////////////////////////////////////////////////////////////////////
    public static class API
    {
        ///////////////////////////////////////////////////////////////////////
        // Признак автоматического выделения памяти
        ///////////////////////////////////////////////////////////////////////
        public const int SCARD_AUTOALLOCATE                     = -1; 

        ///////////////////////////////////////////////////////////////////////
        // Области видимости
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_SCOPE_USER                      = 0x00000000; 
        public const uint SCARD_SCOPE_TERMINAL                  = 0x00000001; 
        public const uint SCARD_SCOPE_SYSTEM                    = 0x00000002; 

        ///////////////////////////////////////////////////////////////////////
        // Состояние считывателя
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_STATE_UNAWARE                   = 0x00000000;  
        public const uint SCARD_STATE_IGNORE                    = 0x00000001;
        public const uint SCARD_STATE_CHANGED                   = 0x00000002;
        public const uint SCARD_STATE_UNKNOWN                   = 0x00000004;
        public const uint SCARD_STATE_UNAVAILABLE               = 0x00000008; 
        public const uint SCARD_STATE_EMPTY                     = 0x00000010;
        public const uint SCARD_STATE_PRESENT                   = 0x00000020; 
        public const uint SCARD_STATE_ATRMATCH                  = 0x00000040; 
        public const uint SCARD_STATE_EXCLUSIVE                 = 0x00000080; 
        public const uint SCARD_STATE_INUSE                     = 0x00000100; 
        public const uint SCARD_STATE_MUTE                      = 0x00000200; 
        public const uint SCARD_STATE_UNPOWERED                 = 0x00000400; 

        ///////////////////////////////////////////////////////////////////////
        // Режим разделения смарт-карты
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_SHARE_EXCLUSIVE                 = 0x00000001;
        public const uint SCARD_SHARE_SHARED                    = 0x00000002; 
        public const uint SCARD_SHARE_DIRECT                    = 0x00000003;

        ///////////////////////////////////////////////////////////////////////
        // Режим отключения от смарт-карты
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_LEAVE_CARD                      = 0x00000000;
        public const uint SCARD_RESET_CARD                      = 0x00000001;
        public const uint SCARD_UNPOWER_CARD                    = 0x00000002;
        public const uint SCARD_EJECT_CARD                      = 0x00000003;

        ///////////////////////////////////////////////////////////////////////
        // Протокол взаимодействия со смарт-картой
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_PROTOCOL_UNDEFINED              = 0x00000000;
        public const uint SCARD_PROTOCOL_T0                     = 0x00000001;
        public const uint SCARD_PROTOCOL_T1                     = 0x00000002;
        public const uint SCARD_PROTOCOL_RAW                    = 0x00010000;

        ///////////////////////////////////////////////////////////////////////
        // Состояния считывателя/смарт-карты
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_UNKNOWN                         = 0x00000000;
        public const uint SCARD_ABSENT                          = 0x00000001;
        public const uint SCARD_PRESENT                         = 0x00000002;
        public const uint SCARD_SWALLOWED                       = 0x00000003;
        public const uint SCARD_POWERED                         = 0x00000004;
        public const uint SCARD_NEGOTIABLE                      = 0x00000005;
        public const uint SCARD_SPECIFIC                        = 0x00000006;

        ///////////////////////////////////////////////////////////////////////
        // Коды ошибок
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_S_SUCCESS			            = 0x00000000;
        public const uint SCARD_F_INTERNAL_ERROR		        = 0x80100001;
        public const uint SCARD_E_CANCELLED		                = 0x80100002;
        public const uint SCARD_E_INVALID_HANDLE		        = 0x80100003;
        public const uint SCARD_E_INVALID_PARAMETER	            = 0x80100004;
        public const uint SCARD_E_INVALID_TARGET		        = 0x80100005;
        public const uint SCARD_E_NO_MEMORY		                = 0x80100006;
        public const uint SCARD_F_WAITED_TOO_LONG		        = 0x80100007;
        public const uint SCARD_E_INSUFFICIENT_BUFFER	        = 0x80100008;
        public const uint SCARD_E_UNKNOWN_READER		        = 0x80100009;
        public const uint SCARD_E_TIMEOUT			            = 0x8010000A;
        public const uint SCARD_E_SHARING_VIOLATION	            = 0x8010000B;
        public const uint SCARD_E_NO_SMARTCARD		            = 0x8010000C;
        public const uint SCARD_E_UNKNOWN_CARD		            = 0x8010000D;
        public const uint SCARD_E_CANT_DISPOSE		            = 0x8010000E;
        public const uint SCARD_E_PROTO_MISMATCH		        = 0x8010000F;
        public const uint SCARD_E_NOT_READY		                = 0x80100010;
        public const uint SCARD_E_INVALID_VALUE		            = 0x80100011;
        public const uint SCARD_E_SYSTEM_CANCELLED	            = 0x80100012;
        public const uint SCARD_F_COMM_ERROR		            = 0x80100013;
        public const uint SCARD_F_UNKNOWN_ERROR		            = 0x80100014;
        public const uint SCARD_E_INVALID_ATR		            = 0x80100015;
        public const uint SCARD_E_NOT_TRANSACTED		        = 0x80100016;
        public const uint SCARD_E_READER_UNAVAILABLE	        = 0x80100017;
        public const uint SCARD_P_SHUTDOWN		                = 0x80100018;
        public const uint SCARD_E_PCI_TOO_SMALL		            = 0x80100019;
        public const uint SCARD_E_READER_UNSUPPORTED	        = 0x8010001A;
        public const uint SCARD_E_DUPLICATE_READER	            = 0x8010001B;
        public const uint SCARD_E_CARD_UNSUPPORTED	            = 0x8010001C;
        public const uint SCARD_E_NO_SERVICE		            = 0x8010001D;
        public const uint SCARD_E_SERVICE_STOPPED		        = 0x8010001E;
        public const uint SCARD_E_UNEXPECTED		            = 0x8010001F;
        public const uint SCARD_E_ICC_INSTALLATION	            = 0x80100020;
        public const uint SCARD_E_ICC_CREATEORDER		        = 0x80100021;
        public const uint SCARD_E_UNSUPPORTED_FEATURE	        = 0x80100022;
        public const uint SCARD_E_DIR_NOT_FOUND		            = 0x80100023;
        public const uint SCARD_E_FILE_NOT_FOUND		        = 0x80100024;
        public const uint SCARD_E_NO_DIR			            = 0x80100025;
        public const uint SCARD_E_NO_FILE			            = 0x80100026;
        public const uint SCARD_E_NO_ACCESS		                = 0x80100027;
        public const uint SCARD_E_WRITE_TOO_MANY		        = 0x80100028;
        public const uint SCARD_E_BAD_SEEK		                = 0x80100029;
        public const uint SCARD_E_INVALID_CHV		            = 0x8010002A;
        public const uint SCARD_E_UNKNOWN_RES_MNG		        = 0x8010002B;
        public const uint SCARD_E_NO_SUCH_CERTIFICATE	        = 0x8010002C;
        public const uint SCARD_E_CERTIFICATE_UNAVAILABLE	    = 0x8010002D;
        public const uint SCARD_E_NO_READERS_AVAILABLE          = 0x8010002E;
        public const uint SCARD_E_COMM_DATA_LOST		        = 0x8010002F;
        public const uint SCARD_E_NO_KEY_CONTAINER	            = 0x80100030;
        public const uint SCARD_E_SERVER_TOO_BUSY		        = 0x80100031;
        public const uint SCARD_W_UNSUPPORTED_CARD	            = 0x80100065;
        public const uint SCARD_W_UNRESPONSIVE_CARD	            = 0x80100066;
        public const uint SCARD_W_UNPOWERED_CARD		        = 0x80100067;
        public const uint SCARD_W_RESET_CARD		            = 0x80100068;
        public const uint SCARD_W_REMOVED_CARD		            = 0x80100069;
        public const uint SCARD_W_SECURITY_VIOLATION	        = 0x8010006A;
        public const uint SCARD_W_WRONG_CHV		                = 0x8010006B;
        public const uint SCARD_W_CHV_BLOCKED		            = 0x8010006C;
        public const uint SCARD_W_EOF			                = 0x8010006D;
        public const uint SCARD_W_CANCELLED_BY_USER	            = 0x8010006E;
        public const uint SCARD_W_CARD_NOT_AUTHENTICATED	    = 0x8010006F;
        public const uint SCARD_W_CACHE_ITEM_NOT_FOUND          = 0x80100070;
        public const uint SCARD_W_CACHE_ITEM_STALE              = 0x80100071;
        public const uint SCARD_W_CACHE_ITEM_TOO_BIG            = 0x80100072;

        ///////////////////////////////////////////////////////////////////////
        // Классы атрибутов
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_CLASS_VENDOR_INFO               = 0x0001;   
        public const uint SCARD_CLASS_COMMUNICATIONS            = 0x0002;   
        public const uint SCARD_CLASS_PROTOCOL                  = 0x0003;   
        public const uint SCARD_CLASS_POWER_MGMT                = 0x0004;   
        public const uint SCARD_CLASS_SECURITY                  = 0x0005;   
        public const uint SCARD_CLASS_MECHANICAL                = 0x0006;   
        public const uint SCARD_CLASS_VENDOR_DEFINED            = 0x0007;   
        public const uint SCARD_CLASS_IFD_PROTOCOL              = 0x0008;   
        public const uint SCARD_CLASS_ICC_STATE                 = 0x0009;   
        public const uint SCARD_CLASS_PERF                      = 0x7FFE;   
        public const uint SCARD_CLASS_SYSTEM                    = 0x7FFF;   

        ///////////////////////////////////////////////////////////////////////
        // Атрибуты считывателя/смарт-карты
        ///////////////////////////////////////////////////////////////////////
        public const uint SCARD_ATTR_VENDOR_NAME                = ((SCARD_CLASS_VENDOR_INFO     << 16) | 0x0100);
        public const uint SCARD_ATTR_VENDOR_IFD_TYPE            = ((SCARD_CLASS_VENDOR_INFO     << 16) | 0x0101);
        public const uint SCARD_ATTR_VENDOR_IFD_VERSION         = ((SCARD_CLASS_VENDOR_INFO     << 16) | 0x0102);
        public const uint SCARD_ATTR_VENDOR_IFD_SERIAL_NO       = ((SCARD_CLASS_VENDOR_INFO     << 16) | 0x0103);
        public const uint SCARD_ATTR_CHANNEL_ID                 = ((SCARD_CLASS_COMMUNICATIONS  << 16) | 0x0110);
        public const uint SCARD_ATTR_ASYNC_PROTOCOL_TYPES       = ((SCARD_CLASS_PROTOCOL        << 16) | 0x0120); 
        public const uint SCARD_ATTR_DEFAULT_CLK                = ((SCARD_CLASS_PROTOCOL        << 16) | 0x0121);
        public const uint SCARD_ATTR_MAX_CLK                    = ((SCARD_CLASS_PROTOCOL        << 16) | 0x0122);
        public const uint SCARD_ATTR_DEFAULT_DATA_RATE          = ((SCARD_CLASS_PROTOCOL        << 16) | 0x0123);
        public const uint SCARD_ATTR_MAX_DATA_RATE              = ((SCARD_CLASS_PROTOCOL        << 16) | 0x0124);
        public const uint SCARD_ATTR_MAX_IFSD                   = ((SCARD_CLASS_PROTOCOL        << 16) | 0x0125); 
        public const uint SCARD_ATTR_SYNC_PROTOCOL_TYPES        = ((SCARD_CLASS_PROTOCOL        << 16) | 0x0126);
        public const uint SCARD_ATTR_POWER_MGMT_SUPPORT         = ((SCARD_CLASS_POWER_MGMT      << 16) | 0x0131);
        public const uint SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE   = ((SCARD_CLASS_SECURITY        << 16) | 0x0140);
        public const uint SCARD_ATTR_USER_AUTH_INPUT_DEVICE     = ((SCARD_CLASS_SECURITY        << 16) | 0x0142);
        public const uint SCARD_ATTR_CHARACTERISTICS            = ((SCARD_CLASS_MECHANICAL      << 16) | 0x0150);
        public const uint SCARD_ATTR_CURRENT_PROTOCOL_TYPE      = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0201);
        public const uint SCARD_ATTR_CURRENT_CLK                = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0202); 
        public const uint SCARD_ATTR_CURRENT_F                  = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0203);
        public const uint SCARD_ATTR_CURRENT_D                  = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0204); 
        public const uint SCARD_ATTR_CURRENT_N                  = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0205); 
        public const uint SCARD_ATTR_CURRENT_W                  = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0206); 
        public const uint SCARD_ATTR_CURRENT_IFSC               = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0207); 
        public const uint SCARD_ATTR_CURRENT_IFSD               = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0208); 
        public const uint SCARD_ATTR_CURRENT_BWT                = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x0209); 
        public const uint SCARD_ATTR_CURRENT_CWT                = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x020A); 
        public const uint SCARD_ATTR_CURRENT_EBC_ENCODING       = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x020B); 
        public const uint SCARD_ATTR_EXTENDED_BWT               = ((SCARD_CLASS_IFD_PROTOCOL    << 16) | 0x020C); 
        public const uint SCARD_ATTR_ICC_PRESENCE               = ((SCARD_CLASS_ICC_STATE       << 16) | 0x0300); 
        public const uint SCARD_ATTR_ICC_INTERFACE_STATUS       = ((SCARD_CLASS_ICC_STATE       << 16) | 0x0301);  
        public const uint SCARD_ATTR_CURRENT_IO_STATE           = ((SCARD_CLASS_ICC_STATE       << 16) | 0x0302); 
        public const uint SCARD_ATTR_ATR_STRING                 = ((SCARD_CLASS_ICC_STATE       << 16) | 0x0303); 
        public const uint SCARD_ATTR_ICC_TYPE_PER_ATR           = ((SCARD_CLASS_ICC_STATE       << 16) | 0x0304); 
        public const uint SCARD_ATTR_ESC_RESET                  = ((SCARD_CLASS_VENDOR_DEFINED  << 16) | 0xA000); 
        public const uint SCARD_ATTR_ESC_CANCEL                 = ((SCARD_CLASS_VENDOR_DEFINED  << 16) | 0xA003); 
        public const uint SCARD_ATTR_ESC_AUTHREQUEST            = ((SCARD_CLASS_VENDOR_DEFINED  << 16) | 0xA005); 
        public const uint SCARD_ATTR_MAXINPUT                   = ((SCARD_CLASS_VENDOR_DEFINED  << 16) | 0xA007); 
        public const uint SCARD_ATTR_DEVICE_UNIT                = ((SCARD_CLASS_SYSTEM          << 16) | 0x0001); 
        public const uint SCARD_ATTR_DEVICE_IN_USE              = ((SCARD_CLASS_SYSTEM          << 16) | 0x0002); 
        public const uint SCARD_ATTR_DEVICE_FRIENDLY_NAME_A     = ((SCARD_CLASS_SYSTEM          << 16) | 0x0003);
        public const uint SCARD_ATTR_DEVICE_SYSTEM_NAME_A       = ((SCARD_CLASS_SYSTEM          << 16) | 0x0004);
        public const uint SCARD_ATTR_DEVICE_FRIENDLY_NAME_W     = ((SCARD_CLASS_SYSTEM          << 16) | 0x0005);
        public const uint SCARD_ATTR_DEVICE_SYSTEM_NAME_W       = ((SCARD_CLASS_SYSTEM          << 16) | 0x0006);
        public const uint SCARD_ATTR_SUPRESS_T1_IFS_REQUEST     = ((SCARD_CLASS_SYSTEM          << 16) | 0x0007);
    }
}
