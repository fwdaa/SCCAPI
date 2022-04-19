package aladdin.capi.jcp;
import aladdin.capi.*;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Фабрика генерации симметричных ключей через алгоритм PBKDF2
///////////////////////////////////////////////////////////////////////////////
public class PBKDF2FactorySpi extends SecretKeyFactorySpi
{
    // конструктор
    public PBKDF2FactorySpi(Provider provider, String name) 
    {  
        // сохранить переданные параметры
        super(provider, name); 
    } 
	@Override protected javax.crypto.SecretKey engineGenerateSecret(KeySpec keySpec) 
		throws InvalidKeySpecException 
    {
        // указать провайдер и имя алгоритма
        Provider provider = getProvider(); String name = getAlgorithm(); 
        
        // при генерации ключа
        if (keySpec instanceof PBEKeySpec) { PBEKeySpec pbeKeySpec = (PBEKeySpec)keySpec; 
        
            // определить размер ключа в битах
            int keySize = pbeKeySpec.getKeyLength(); if ((keySize % 8) != 0)
            {
                // при ошибке выбросить исключение 
                throw new InvalidKeySpecException(); 
            }
            // определить размер ключа в байтах
            keySize = (keySize != 0) ? (keySize / 8) : -1; 
            
            // указать параметры алгоритма
            AlgorithmParameterSpec pbeParamSpec = new PBEParameterSpec(
                pbeKeySpec.getSalt(), pbeKeySpec.getIterationCount()); 
            try { 
                // создать параметры алгоритма
                AlgorithmParameters parameters = provider.createParameters(name, pbeParamSpec); 
                
                // создать алгоритм наследования ключа
                try (KeyDerive keyDerive = (KeyDerive)provider.createAlgorithm(
                    name, parameters, KeyDerive.class))
                {
                    // проверить наличие алгоритма
                    if (keyDerive == null) throw new UnsupportedOperationException(); 
                    
                    // получить фабрику кодирования ключа
                    SecretKeyFactory keyFactory = SecretKeyFactory.GENERIC; 
                    
                    // создать ключ
                    try (ISecretKey password = aladdin.capi.SecretKey.fromPassword(
                        new String(pbeKeySpec.getPassword()), "UTF-8"))
                    {
                        // создать ключ 
                        try (ISecretKey secretKey = keyDerive.deriveKey(
                            password, null, keyFactory, keySize))
                        {
                            // зарегистрировать симметричный ключ
                            return new SecretKey(provider, null, secretKey); 
                        }
                    }
                }
            }
            // обработать возможное исключение
            catch (InvalidParameterSpecException e) { throw new InvalidKeySpecException(e.getMessage()); }
            catch (InvalidKeyException           e) { throw new InvalidKeySpecException(e.getMessage()); }
            catch (IOException                   e) { throw new InvalidKeySpecException(e.getMessage()); }
        }
        // вызвать базовую функцию
        return super.engineGenerateSecret(keySpec);
    }
}
