package aladdin.capi.stb.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ СТБ 34.101
///////////////////////////////////////////////////////////////////////////
public class STB34101 extends SecretKeyFactory
{
    // тип ключа
    public static final SecretKeyFactory INSTANCE = new STB34101(); 
        
    // конструктор
    private STB34101() { super("STB34101"); }
    
	// размер ключей
	@Override public final int[] keySizes() { return new int[] { 16, 24, 32 }; }
}
