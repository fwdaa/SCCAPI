namespace Aladdin.PKCS11
{
    ///////////////////////////////////////////////////////////////////////////
    // Информация о версии
    ///////////////////////////////////////////////////////////////////////////
    public class Version 
    {
	    private byte major; // старший номер версии
	    private byte minor; // младший номер версии

	    // конструктор
	    public Version(API.CK_VERSION version)
	    {
		    // сохранить номера версии
		    this.major = version.major; this.minor = version.minor; 
	    }
	    // старший и младший номер версии
	    public byte Major { get { return major; } }  
	    public byte Minor { get { return minor; } }  
    };
}
