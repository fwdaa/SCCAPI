using System;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Фабрика создания генераторов случайных данных
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class ConfigRandFactory : RefObject, IRandFactory
    {
        // фабрика создания генераторов случайных данных
        private IRandFactory randFactory; private bool critical; 

        // конструктор
        public ConfigRandFactory(IRandFactory randFactory, bool critical)
        {
            // сохранить переданные параметры
            this.randFactory = RefObject.AddRef(randFactory); this.critical = critical; 
        }
        // освободить используемые ресурсы
        protected override void OnDispose()
        {
            // освободить используемые ресурсы
            RefObject.Release(randFactory); base.OnDispose(); 
        }
        // создать генератор случайных данных
        public virtual IRand CreateRand(object window)
        {
            // создать генератор случайных данных
            try { return randFactory.CreateRand(window); }

            // обработать возможную ошибку
            catch { if (critical) throw; return null; }
        }
    }
}
