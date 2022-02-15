package aladdin.pkcs11;
import aladdin.pkcs11.jni.*;

///////////////////////////////////////////////////////////////////////////
// Информация о сеансе
///////////////////////////////////////////////////////////////////////////
public class  SessionInfo
{
	private final long slotID;	// идентификатор устройства
	private final long state;	// состояние сеанса
	private final long flags;	// атрибуты сеанса

	// конструктор
	SessionInfo(CK_SESSION_INFO info) { flags = info.flags;

		// сохранить идентификатор устройства и состояние сеанса
		slotID = info.slotID; state = info.state; 
	}
	public final long slotID() { return slotID;	}  
	public final long state	() { return state;	}  
	public final long flags	() { return flags;	}  
}; 
