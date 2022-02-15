package aladdin.capi.ansi.cipher;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования Skipjack
///////////////////////////////////////////////////////////////////////////
public final class Skipjack extends BlockCipher
{
    // конструктор
    public Skipjack(Cipher engine, PaddingMode padding) { super(engine, padding); }
}
