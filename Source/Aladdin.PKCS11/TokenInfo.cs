using System;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация о смарт-карте
    ///////////////////////////////////////////////////////////////////////////
    public class TokenInfo
    {
	    private Version	hardwareVersion;		// версия аппаратного обеспечения
	    private Version	firmwareVersion;		// версия программного обеспечения
	    private String  manufacturerID;			// имя производителя
	    private String  model;					// модель смарт-карты
	    private Byte[]  serialNumber;			// серийный номер смарт-карты
	    private String	label;					// метка смарт-карты
	    private UInt64	flags;					// атрибуты смарт-карты
	    private Int32	ulTotalPublicMemory;	// размер открытой памяти
	    private Int32	ulFreePublicMemory;		// оставшийся размер открытой памяти
	    private Int32	ulTotalPrivateMemory;	// размер закрытой памяти
	    private Int32	ulFreePrivateMemory;	// оставшийся размер закрытой памяти
	    private Int32	ulMaxPinLen;			// максимальная длина пин-кода
	    private Int32	ulMinPinLen;			// минимальная длина пин-кода
	    private Int32	ulMaxSessionCount;		// максимальное число сеансов
	    private Int32	ulSessionCount;			// число открытых сеансов
	    private Int32	ulMaxRwSessionCount;	// максимальное число сеансов для записи
	    private Int32	ulRwSessionCount;		// число открытых сеансов для записи

	    // конструктор
	    public TokenInfo(API32.CK_TOKEN_INFO info) { flags = info.flags; 
	     
		    // сохранить номер версии аппаратного и программного обеспечения
		    hardwareVersion = new Version(info.hardwareVersion); 
		    firmwareVersion = new Version(info.firmwareVersion);

		    // сохранить имя производителя, модель и метку
		    manufacturerID  = Encoding.DecodeString(info.manufacturerID, 32); 
		    model			= Encoding.DecodeString(info.model,	         16); 
		    label           = Encoding.DecodeString(info.label,          32); 

            // раскодировать серийный номер
		    serialNumber = Encoding.FromHex(Encoding.DecodeString(info.serialNumber, 16)); 

		    // сохранить размеры памяти
		    ulTotalPublicMemory  = info.ulTotalPublicMemory; 
		    ulFreePublicMemory   = info.ulFreePublicMemory; 
		    ulTotalPrivateMemory = info.ulTotalPrivateMemory; 
		    ulFreePrivateMemory  = info.ulFreePrivateMemory; 

		    // сохранить размеры пин-кодов
		    ulMaxPinLen = info.ulMaxPinLen; ulMinPinLen = info.ulMinPinLen; 

		    // сохранить число сеансов
		    ulMaxSessionCount   = info.ulMaxSessionCount; 
		    ulSessionCount      = info.ulSessionCount; 
		    ulMaxRwSessionCount = info.ulMaxRwSessionCount; 
		    ulRwSessionCount    = info.ulRwSessionCount; 
	    }
	    // конструктор
	    public TokenInfo(API64.CK_TOKEN_INFO info) { flags = info.flags; 
	     
		    // сохранить номер версии аппаратного и программного обеспечения
		    hardwareVersion = new Version(info.hardwareVersion); 
		    firmwareVersion = new Version(info.firmwareVersion);

		    // сохранить имя производителя, модель и метку
		    manufacturerID  = Encoding.DecodeString(info.manufacturerID, 32); 
		    model			= Encoding.DecodeString(info.model,	         16); 
		    label           = Encoding.DecodeString(info.label,          32); 

            // раскодировать серийный номер
		    serialNumber = Encoding.FromHex(Encoding.DecodeString(info.serialNumber, 16)); 

		    // сохранить размеры памяти
		    ulTotalPublicMemory  = (Int32)info.ulTotalPublicMemory; 
		    ulFreePublicMemory   = (Int32)info.ulFreePublicMemory; 
		    ulTotalPrivateMemory = (Int32)info.ulTotalPrivateMemory; 
		    ulFreePrivateMemory  = (Int32)info.ulFreePrivateMemory; 

		    // сохранить размеры пин-кодов
		    ulMaxPinLen = (Int32)info.ulMaxPinLen; ulMinPinLen = (Int32)info.ulMinPinLen; 

		    // сохранить число сеансов
		    ulMaxSessionCount   = (Int32)info.ulMaxSessionCount; 
		    ulSessionCount      = (Int32)info.ulSessionCount; 
		    ulMaxRwSessionCount = (Int32)info.ulMaxRwSessionCount; 
		    ulRwSessionCount    = (Int32)info.ulRwSessionCount; 
	    }
	    public Version	HardwareVersion		{ get { return hardwareVersion;		} }  
	    public Version	FirmwareVersion		{ get { return firmwareVersion;		} }  
	    public String	ManufacturerID		{ get { return manufacturerID;		} }  
	    public String	Model				{ get { return model;				} }  
	    public Byte[]	SerialNumber		{ get { return serialNumber;		} }
	    public String	Label				{ get { return label;				} }  
	    public UInt64	Flags				{ get { return flags;				} }  
	    public Int32	TotalPublicMemory	{ get { return ulTotalPublicMemory;	} }  
	    public Int32	FreePublicMemory	{ get { return ulFreePublicMemory;	} }  
	    public Int32	TotalPrivateMemory	{ get { return ulTotalPrivateMemory;} }  
	    public Int32	FreePrivateMemory	{ get { return ulFreePrivateMemory;	} }  
	    public Int32	MaxPinLen			{ get { return ulMaxPinLen;			} }  
	    public Int32	MinPinLen			{ get { return ulMinPinLen;			} }  
	    public Int32	MaxSessionCount		{ get { return ulMaxSessionCount;	} }  
	    public Int32	SessionCount		{ get { return ulSessionCount;		} }  
	    public Int32	MaxRwSessionCount	{ get { return ulMaxRwSessionCount;	} }  
	    public Int32	RwSessionCount		{ get { return ulRwSessionCount;	} }  
    }; 
}
