using System;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация о считывателе
    ///////////////////////////////////////////////////////////////////////////
    public class SlotInfo
    {
	    private Version  hardwareVersion;	// версия аппаратного обеспечения
	    private Version  firmwareVersion;	// версия программного обеспечения
	    private String   manufacturerID;	// имя производителя
	    private String   slotDescription;	// описание считывателя
	    private UInt64   flags;			    // атрибуты считывателя

	    // конструктор
	    public SlotInfo(API32.CK_SLOT_INFO info) { flags = info.flags; 

		    // сохранить номер версии аппаратного и программного обеспечения
		    hardwareVersion = new Version(info.hardwareVersion); 
		    firmwareVersion = new Version(info.firmwareVersion);

		    // сохранить имя производителя и описание считывателя
		    manufacturerID  = Encoding.DecodeString(info.manufacturerID , 32); 
		    slotDescription = Encoding.DecodeString(info.slotDescription, 64); 
	    }
	    // конструктор
	    public SlotInfo(API64.CK_SLOT_INFO info) { flags = info.flags; 

		    // сохранить номер версии аппаратного и программного обеспечения
		    hardwareVersion = new Version(info.hardwareVersion); 
		    firmwareVersion = new Version(info.firmwareVersion);

		    // сохранить имя производителя и описание считывателя
		    manufacturerID  = Encoding.DecodeString(info.manufacturerID , 32); 
		    slotDescription = Encoding.DecodeString(info.slotDescription, 64); 
	    }
	    public Version HardwareVersion	{ get { return hardwareVersion;	} }  
	    public Version FirmwareVersion	{ get { return firmwareVersion;	} }  
	    public String  ManufacturerID	{ get { return manufacturerID;	} }  
	    public String  SlotDescription	{ get { return slotDescription;	} }  
	    public UInt64  Flags			{ get { return flags;			} }  
    }; 
}
