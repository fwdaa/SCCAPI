using System;

namespace Aladdin.ISO7816
{
    ///////////////////////////////////////////////////////////////////////////////
    // Блокировка доступа к карте
    ///////////////////////////////////////////////////////////////////////////////
    public sealed class CardLock : Disposable
    {
        // используемый сеанс
        private CardSession session; 
    
        // конструктор
        public CardLock(CardSession session)
        { 
            // захватить блокировку
            session.Lock(); this.session = session; 
        } 
        // освободить блокировку
        protected override void OnDispose() { session.Unlock(); base.OnDispose(); }
    }
}
