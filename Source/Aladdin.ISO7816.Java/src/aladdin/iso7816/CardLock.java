package aladdin.iso7816;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Блокировка доступа к карте
///////////////////////////////////////////////////////////////////////////////
public final class CardLock extends Disposable
{
    // используемый сеанс
    private final CardSession session; 
    
    // конструктор
    public CardLock(CardSession session) throws IOException 
    { 
        // захватить блокировку
        session.lock(); this.session = session; 
    } 
    // освободить блокировку
    @Override protected void onClose() throws IOException
    { 
        // освободить блокировку
        session.unlock(); super.onClose();
    }
}
