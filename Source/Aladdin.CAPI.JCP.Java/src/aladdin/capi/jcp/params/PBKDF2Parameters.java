package aladdin.capi.jcp.params;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs5.*;
import aladdin.capi.jcp.*;
import java.io.*;
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма PBKDF2
///////////////////////////////////////////////////////////////////////////////
public class PBKDF2Parameters extends AlgorithmParametersSpi
{    
    // параметры адгоритма
    private final AlgorithmIdentifier prf; private PBEParameterSpec paramSpec; 
    
    // конструктор
    public PBKDF2Parameters(Provider provider, String name) 
    { 
        // инициализировать переменные
        super(provider, aladdin.asn1.iso.pkcs.pkcs5.OID.PBKDF2); paramSpec = null; 
        
        // проверить имя алгоритма
        if (name.equalsIgnoreCase("PBKDF2WithHmacSHA1")) prf = null; 
        
        // при ошибке выбросить исключение
        else throw new UnsupportedOperationException(); 
    } 
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // проверить тип параметров
        if (!(paramSpec instanceof PBEParameterSpec)) throw new InvalidParameterSpecException(); 
        
        // сохранить параметры алгоритма
        this.paramSpec = (PBEParameterSpec)paramSpec; 
        
        // закодировать параметры
        IEncodable encodable = new PBKDF2Parameter(
            new OctetString(this.paramSpec.getSalt()), 
            new Integer(this.paramSpec.getIterationCount()), null, prf
        ); 
        // сохранить закодированное представление
        try { engineInit(encodable.encoded()); }
            
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterSpecException(e.getMessage()); }
	}
    // извлечь параметры
    @SuppressWarnings({"unchecked"}) 
    @Override protected <T extends AlgorithmParameterSpec> 
        T engineGetParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException 
    {
        // вернуть параметры
        if (specType.isAssignableFrom(paramSpec.getClass())) return (T)paramSpec; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
