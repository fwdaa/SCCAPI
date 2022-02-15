using System;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Фабрика создания генераторов случайных данных
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class RandFactory : RefObject, IRandFactory
    {
        // конструктор
        public RandFactory(IRand rand)
         
            // сохранить переданные параметры 
            { this.rand = RefObject.AddRef(rand); } private IRand rand; 
        
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // вызвать базовую функцию
            RefObject.Release(rand); base.OnDispose();
        }
        // создать генератор случайных данных
        public virtual IRand CreateRand(object window) 
        { 
            // вернуть генератор случайных данных
            return RefObject.AddRef(rand); 
        } 
    }
}
