package aladdin.capi.pkcs11.aks;
import aladdin.pkcs11.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////
public class Provider extends aladdin.capi.ansi.pkcs11.Provider
{
    // интерфейс вызова функций
    private final Module module; 
    
	// конструктор
	public Provider(String path) throws IOException 
    { 
        // сохранить переданные параметры
        super("AKS PKCS11 Cryptographic Provider", true);
        
        // открыть модуль
        module = new Module(path); 
    }
	@Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        module.close(); super.onClose();
    } 	
    // интерфейс вызова функций
	@Override public Module module() { return module; } 
    
    // тип структуры передачи параметров механизма PBKDF2
    @Override protected aladdin.capi.pkcs11.pbe.PBKDF2.ParametersType pbkdf2ParametersType() 
    {
        // тип структуры передачи параметров механизма PBKDF2
        return aladdin.capi.pkcs11.pbe.PBKDF2.ParametersType.PARAMS_LONG; 
    }
}
