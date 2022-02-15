package aladdin.pkcs11;
import aladdin.pkcs11.jni.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Информация о считывателе
///////////////////////////////////////////////////////////////////////////
public class SlotInfo
{
	private final Version hardwareVersion;	// версия аппаратного обеспечения
	private final Version firmwareVersion;	// версия программного обеспечения
	private final String  manufacturerID;	// имя производителя
	private final String  slotDescription;	// описание считывателя
	private final long	  flags;			// атрибуты считывателя

	// конструктор
	public SlotInfo(CK_SLOT_INFO info) throws IOException { flags = info.flags; 

		// сохранить номер версии аппаратного и программного обеспечения
		hardwareVersion = new Version(info.hardwareVersion); 
		firmwareVersion = new Version(info.firmwareVersion);

		// сохранить имя производителя и описание считывателя
		manufacturerID  = Encoding.decodeString(info.manufacturerID ); 
		slotDescription = Encoding.decodeString(info.slotDescription); 
	}
	public final Version    hardwareVersion () { return hardwareVersion;	}  
	public final Version    firmwareVersion () { return firmwareVersion;	}  
	public final String     manufacturerID	() { return manufacturerID;		}  
	public final String     slotDescription	() { return slotDescription;	}  
	public final long		flags           () { return flags;				}  
}; 
