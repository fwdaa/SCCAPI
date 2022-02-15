package aladdin.capi.pkcs11;
import aladdin.pkcs11.jni.*;

///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма
///////////////////////////////////////////////////////////////////////////
public class Mechanism
{
	// алгоритм и его параметы
	private final long id; private final Object parameters;

	// конструктор
	public Mechanism(CK_MECHANISM mechanism) 
	{ 
		// сохранить алгоритм и его параметры 
		this.id = mechanism.mechanism; parameters = mechanism.parameter; 
	}
	// конструктор
	public Mechanism(long id) 
	{ 
		// сохранить алгоритм и его параметры 
		this.id = id; this.parameters = null; 
	}
	// конструктор
	public Mechanism(long id, long parameters) 
	{ 
		// сохранить алгоритм и его параметры 
		this.id = id; this.parameters = parameters; 
	}
	// конструктор
	public Mechanism(long id, Object parameters) 
	{ 
		// сохранить алгоритм и его параметры 
		this.id = id; this.parameters = parameters; 
	}
	// тип и значение атрибута
	public final long 	id        () { return id;         }  
	public final Object parameters() { return parameters; }  
    
    // преобразовать тип значения
    public final int  intParameter () { return ((Long)parameters).intValue (); } 
    public final long longParameter() { return ((Long)parameters).longValue(); } 

	// преобразовать тип параметров
	public final CK_MECHANISM convert()
	{
		// преобразовать тип параметров
		return new CK_MECHANISM(id, parameters); 
	}
} 
