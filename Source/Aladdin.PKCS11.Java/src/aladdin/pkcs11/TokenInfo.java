package aladdin.pkcs11;
import aladdin.pkcs11.jni.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Информация о смарт-карте
///////////////////////////////////////////////////////////////////////////
public class TokenInfo
{
	private final Version	hardwareVersion;	// версия аппаратного обеспечения
	private final Version	firmwareVersion;	// версия программного обеспечения
	private final String    manufacturerID;     // имя производителя
	private final String    model;              // модель смарт-карты
	private final byte[]    serialNumber;       // серийный номер смарт-карты
	private final String	label;				// метка смарт-карты
	private final long		flags;				// атрибуты смарт-карты
	private final int		totalPublicMemory;	// размер открытой памяти
	private final int		freePublicMemory;	// оставшийся размер открытой памяти
	private final int		totalPrivateMemory;	// размер закрытой памяти
	private final int		freePrivateMemory;	// оставшийся размер закрытой памяти
	private final int		maxPinLen;			// максимальная длина пин-кода
	private final int		minPinLen;			// минимальная длина пин-кода
	private final int       maxSessionCount;	// максимальное число сеансов
	private final int       sessionCount;		// число открытых сеансов
	private final int       maxRwSessionCount;  // максимальное число сеансов для записи
	private final int       rwSessionCount;     // число открытых сеансов для записи

	// конструктор
	public TokenInfo(CK_TOKEN_INFO info) throws IOException { flags = info.flags; 
		
		// сохранить номер версии аппаратного и программного обеспечения
		hardwareVersion = new Version(info.hardwareVersion); 
		firmwareVersion = new Version(info.firmwareVersion);
        
		// сохранить имя производителя, модель и серийный номер
		manufacturerID  = Encoding.decodeString(info.manufacturerID	); 
		model			= Encoding.decodeString(info.model			); 
		label           = Encoding.decodeString(info.label          ); 

        // раскодировать серийный номер
		serialNumber = Encoding.fromHex(Encoding.decodeString(info.serialNumber)); 
            
		// сохранить размеры памяти
		totalPublicMemory  = info.ulTotalPublicMemory; 
		freePublicMemory   = info.ulFreePublicMemory; 
		totalPrivateMemory = info.ulTotalPrivateMemory; 
		freePrivateMemory  = info.ulFreePrivateMemory; 

		// сохранить размеры пин-кодов
		maxPinLen = info.ulMaxPinLen; minPinLen = info.ulMinPinLen; 

		// сохранить число сеансов
		maxSessionCount   = info.ulMaxSessionCount; 
		sessionCount      = info.ulSessionCount; 
		maxRwSessionCount = info.ulMaxRwSessionCount; 
		rwSessionCount    = info.ulRwSessionCount; 
	}
	public final Version	hardwareVersion		() { return hardwareVersion;	}  
	public final Version	firmwareVersion		() { return firmwareVersion;	}  
	public final String     manufacturerID	    () { return manufacturerID;     }  
	public final String     model			    () { return model;              }  
	public final byte[]     serialNumber	    () { return serialNumber;       }
	public final String		label				() { return label;              }  
	public final long		flags				() { return flags;				}  
	public final int		totalPublicMemory	() { return totalPublicMemory;	}  
	public final int		freePublicMemory	() { return freePublicMemory;	}  
	public final int		totalPrivateMemory	() { return totalPrivateMemory;	}  
	public final int		freePrivateMemory	() { return freePrivateMemory;	}  
	public final int		maxPinLen			() { return maxPinLen;			}  
	public final int		minPinLen			() { return minPinLen;			}  
	public final int		maxSessionCount		() { return maxSessionCount;	}  
	public final int		sessionCount		() { return sessionCount;		}  
	public final int		maxRwSessionCount	() { return maxRwSessionCount;	}  
	public final int		rwSessionCount		() { return rwSessionCount;		}  
}; 
