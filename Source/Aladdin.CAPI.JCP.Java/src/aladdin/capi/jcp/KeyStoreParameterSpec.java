package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.security.spec.*; 
		
///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма с областью видимости
///////////////////////////////////////////////////////////////////////////////
public class KeyStoreParameterSpec implements AlgorithmParameterSpec 
{
    // область видимости и закодированные параметры
    private final SecurityStore scope; private final java.security.AlgorithmParameters parameters;
    
	// конструктор
	public KeyStoreParameterSpec(SecurityStore scope, java.security.AlgorithmParameters parameters)
	{  
		// сохранить переданные параметры
		this.scope = scope; this.parameters = parameters; 
    } 
	// область видимости
	public final SecurityStore getScope() { return scope; } 

    // параметры алгоритма
    public final java.security.AlgorithmParameters parameters() { return parameters; }
}
