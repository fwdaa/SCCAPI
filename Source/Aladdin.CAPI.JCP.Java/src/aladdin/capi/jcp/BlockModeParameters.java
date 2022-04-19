package aladdin.capi.jcp;
import aladdin.asn1.*;
import java.io.*;
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры режима блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
public class BlockModeParameters extends AlgorithmParametersSpi
{
    // параметры блочного алгоритма шифрования
    private BlockModeParameterSpec paramSpec; 
    
    // конструктор
    public BlockModeParameters(Provider provider, String algorithm) 
    { 
        // инициализировать переменные
        super(provider, algorithm); paramSpec = null;
    } 
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // в зависимости от типа параметров
        if (paramSpec instanceof BlockModeParameterSpec) 
        {
            // выполнить преобразование типа
            this.paramSpec = (BlockModeParameterSpec)paramSpec; 
        }
        // в зависимости от типа параметров
        else if (paramSpec instanceof IvParameterSpec)
        {
            // извлечь синхропосылку
            byte[] iv = ((IvParameterSpec)paramSpec).getIV(); 

            // сохранить параметры
            this.paramSpec = new BlockModeParameterSpec(null, iv); 
        }
        // в зависимости от типа параметров
        else if (paramSpec == null) 
        {
            // сохранить параметры
            this.paramSpec = new BlockModeParameterSpec(null, null); 
        }
        // при ошибке выбросить исключение
        else throw new InvalidParameterSpecException(); 
        
        // получить параметры алгоритма шифрования
        java.security.AlgorithmParameters parameters = this.paramSpec.cipherParameters(); 
        try { 
            // указать закодированное представление по умолчанию
            byte[] encoded = Null.INSTANCE.encoded(); 
        
            // указать закодированное представление
            if (parameters != null) encoded = parameters.getEncoded("ASN.1"); 
        
            // сохранить закодированное представление
            engineInit(encoded); 
        }
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
        
        // при запросе синхропосылки
        if (specType.isAssignableFrom(IvParameterSpec.class))
        {
            // извлечь синхропосылку
            byte[] iv = paramSpec.getIV(); 
            
            // проверить наличие синхропосылки
            if (iv == null) throw new InvalidParameterSpecException();   

            // вернуть синхропосылку
            return (T)new IvParameterSpec(iv); 
        }
        // получить параметры алгоритма шифрования
        java.security.AlgorithmParameters parameters = paramSpec.cipherParameters(); 
        
        // проверить наличие параметров 
        if (parameters == null) throw new InvalidParameterSpecException(); 
        
        // извлчеь параметры
        return parameters.getParameterSpec(specType); 
    }
}
