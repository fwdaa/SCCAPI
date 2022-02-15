package aladdin.capi.ansi.keys;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Ключ Skipjack
///////////////////////////////////////////////////////////////////////////
public class Skipjack extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new Skipjack(); 
        
    // конструктор
    private Skipjack() { super("Skipjack"); }
    
    // размер ключей
	@Override public final int[] keySizes() { return new int[] { 10 }; }
}
