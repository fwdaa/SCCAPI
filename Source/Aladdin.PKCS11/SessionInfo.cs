using System;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация о сеансе
    ///////////////////////////////////////////////////////////////////////////
    public class SessionInfo
    {
	    private UInt64 slotID;		// идентификатор устройства
	    private UInt64 state;		// состояние сеанса
	    private UInt64 flags;		// атрибуты сеанса

	    // конструктор
	    public SessionInfo(API32.CK_SESSION_INFO info) 
        { 
		    // сохранить идентификатор устройства и состояние сеанса
		    slotID = info.slotID; state = info.state; flags = info.flags;
	    }
	    // конструктор
	    public SessionInfo(API64.CK_SESSION_INFO info) 
        { 
		    // сохранить идентификатор устройства и состояние сеанса
		    slotID = info.slotID; state = info.state; flags = info.flags;
	    }
	    public UInt64 SlotID { get { return slotID;	} }  
	    public UInt64 State	 { get { return state;	} }  
	    public UInt64 Flags	 { get { return flags;	} }  
    }; 
}
