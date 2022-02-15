using System;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация об алгоритме
    ///////////////////////////////////////////////////////////////////////////
    public class MechanismInfo
    {
	    private UInt64 flags;		    // атрибуты алгоритма
	    private Int32  ulMinKeySize;	// минимальный размер ключей
	    private Int32  ulMaxKeySize;	// максимальный размер ключей
		
	    // конструктор
	    public MechanismInfo(API32.CK_MECHANISM_INFO info) { flags = info.flags;

		    // сохранить минимальный и максимальный размер ключей
		    ulMinKeySize = info.ulMinKeySize; ulMaxKeySize = info.ulMaxKeySize; 
	    }
	    // конструктор
	    public MechanismInfo(API64.CK_MECHANISM_INFO info) { flags = info.flags;

		    // сохранить минимальный и максимальный размер ключей
		    ulMinKeySize = (Int32)info.ulMinKeySize; ulMaxKeySize = (Int32)info.ulMaxKeySize; 
	    }
	    public UInt64 Flags		    { get { return flags;		    } }  
	    public Int32  MinKeySize	{ get { return ulMinKeySize;	} }  
	    public Int32  MaxKeySize	{ get { return ulMaxKeySize;	} }  
    }; 
}
