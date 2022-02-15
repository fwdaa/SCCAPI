package aladdin.pkcs11;
import aladdin.pkcs11.jni.*;

///////////////////////////////////////////////////////////////////////////
// Информация об алгоритме
///////////////////////////////////////////////////////////////////////////
public class MechanismInfo
{
	private final long flags;		// атрибуты алгоритма
	private final int  minKeySize;	// минимальный размер ключей
	private final int  maxKeySize;	// максимальный размер ключей
		
	// конструктор
	public MechanismInfo(CK_MECHANISM_INFO info) { flags = info.flags;

		// сохранить минимальный и максимальный размер ключей
		minKeySize = info.ulMinKeySize; maxKeySize = info.ulMaxKeySize; 
	}
	public final long flags		() { return flags;		}  
	public final int  minKeySize() { return minKeySize;	}  
	public final int  maxKeySize() { return maxKeySize;	}  
}; 
