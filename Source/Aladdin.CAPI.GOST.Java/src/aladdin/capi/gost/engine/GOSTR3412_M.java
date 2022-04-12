package aladdin.capi.gost.engine;
import aladdin.math.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ГОСТ P34.12-2015 (размер блока 8 байт)
///////////////////////////////////////////////////////////////////////////
public class GOSTR3412_M extends GOST28147
{
    // способ кодирования чисел
    public static final Endian ENDIAN = Endian.BIG_ENDIAN;
    
    // конструктор
    public GOSTR3412_M(byte[] sbox) { super(sbox, ENDIAN); }
}
