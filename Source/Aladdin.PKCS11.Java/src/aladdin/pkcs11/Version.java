package aladdin.pkcs11;
import aladdin.pkcs11.jni.*;

///////////////////////////////////////////////////////////////////////////
// Информация о версии
///////////////////////////////////////////////////////////////////////////
public class Version 
{
	private final byte major; // старший номер версии
	private final byte minor; // младший номер версии

	// конструктор
	public Version(CK_VERSION version)
	{
		// сохранить номера версии
		this.major = version.major; this.minor = version.minor; 
	}
	// старший и младший номер версии
	public final byte major() { return major; }  
	public final byte minor() { return minor; }  
};
