package aladdin.capi.stb.stb34101;
import aladdin.capi.*; 
import java.security.spec.*;
import java.math.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Личный ключ алгоритма СТБ 34.101
///////////////////////////////////////////////////////////////////////////
public class PrivateKey extends aladdin.capi.PrivateKey implements IPrivateKey
{
    // номер версии для сериализации
    private static final long serialVersionUID = 611694123914755308L;
    
    // параметры ключа и секретное значение
    private final Parameters parameters; private final BigInteger d;
    
    // конструктор
	public PrivateKey(Factory factory, SecurityObject scope, 
        String keyOID, IParameters parameters, BigInteger d) 
	{ 	
        // сохранить переданные параметры
		super(factory, scope, keyOID); this.d = d;  
        
        // сохранить переданные параметры
        this.parameters = Parameters.convert(parameters); 
    } 
    // параметры ключа
	@Override public final IParameters parameters() { return parameters; } 
    // секретное значение
	@Override public final BigInteger getS() { return d; } 
}
