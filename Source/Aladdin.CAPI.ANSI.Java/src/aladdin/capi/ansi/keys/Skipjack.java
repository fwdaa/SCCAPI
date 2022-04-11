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
    public Skipjack() { super(new int[] {10}); }
}
