package aladdin.capi.stb.keys;
import aladdin.capi.*;

///////////////////////////////////////////////////////////////////////////
// Ключ СТБ 34.101
///////////////////////////////////////////////////////////////////////////
public class STB34101 extends SecretKeyFactory
{
    // конструктор
    public STB34101(int[] keySizes) { super(keySizes); }
    // конструктор
    public STB34101() { super(new int[] { 16, 24, 32 }); }
    
    // ограничить размер ключей
    @Override public SecretKeyFactory narrow(int[] keySizes) { return new STB34101(keySizes); }
}
