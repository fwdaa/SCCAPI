package aladdin.pkcs11;
import aladdin.pkcs11.jni.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Информация о модуле
///////////////////////////////////////////////////////////////////////////
public class Info 
{
	private final String  path;				// путь к файлу модуля
	private final Version cryptokiVersion;	// номер версии интерфейса 
	private final Version libraryVersion;		// номер версии модуля
	private final String  manufacturerID;		// имя производителя
	private final String  libraryDescription;	// описание модуля

	// конструктор
	public Info(CK_INFO info, String path) throws IOException { this.path = path; 

		// сохранить номер версии интерфейса и модуля
		cryptokiVersion = new Version(info.cryptokiVersion); 
		libraryVersion  = new Version(info.libraryVersion );
		
		// сохранить имя производителя и описание модуля
		manufacturerID     = Encoding.decodeString(info.manufacturerID    ); 
		libraryDescription = Encoding.decodeString(info.libraryDescription); 
	}
	public final String		path				() { return path;				}  
	public final Version	cryptokiVersion		() { return cryptokiVersion;	}  
	public final Version	libraryVersion		() { return libraryVersion;		}  
	public final String		manufacturerID		() { return manufacturerID;		}  
	public final String		libraryDescription	() { return libraryDescription; }  
}; 
