using System;

namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация о модуле
    ///////////////////////////////////////////////////////////////////////////
    public struct Info 
    {
	    private Version cryptokiVersion;	// номер версии интерфейса 
	    private Version libraryVersion;		// номер версии модуля
	    private String  manufacturerID;		// имя производителя
	    private String  libraryDescription;	// описание модуля

	    // конструктор
	    public Info(API32.CK_INFO info) 
	    {
		    // сохранить номер версии интерфейса и модуля
		    cryptokiVersion = new Version(info.cryptokiVersion); 
		    libraryVersion  = new Version(info.libraryVersion );

		    // сохранить имя производителя и описание модуля
		    manufacturerID     = Encoding.DecodeString(info.manufacturerID,     32); 
		    libraryDescription = Encoding.DecodeString(info.libraryDescription, 32); 
	    }
	    // конструктор
	    public Info(API64.CK_INFO info) 
	    {
		    // сохранить номер версии интерфейса и модуля
		    cryptokiVersion = new Version(info.cryptokiVersion); 
		    libraryVersion  = new Version(info.libraryVersion );

		    // сохранить имя производителя и описание модуля
		    manufacturerID     = Encoding.DecodeString(info.manufacturerID,     32); 
		    libraryDescription = Encoding.DecodeString(info.libraryDescription, 32); 
	    }
	    public Version CryptokiVersion	  { get { return cryptokiVersion;	 }}  
	    public Version LibraryVersion	  { get { return libraryVersion;	 }}  
	    public String  ManufacturerID	  { get { return manufacturerID;	 }} 
	    public String  LibraryDescription { get { return libraryDescription; }}  
    }; 
}
