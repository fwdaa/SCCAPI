package aladdin.capi;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Провайдер объектов
///////////////////////////////////////////////////////////////////////////
public interface IProvider extends IRefObject
{
    // имя провайдера 
    String name();  

	// перечислить хранилища объектов
	String[] enumerateStores(Scope scope); 
    // получить хранилище объекта
    SecurityStore openStore(Scope scope, String storeName) throws IOException;     

    // перечислить все объекты
	SecurityInfo[] enumerateAllObjects(Scope scope); 
}
