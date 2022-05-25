using System;
using System.Diagnostics.CodeAnalysis;
using Aladdin.PKCS11; 

namespace Aladdin.CAPI.PKCS11
{
	///////////////////////////////////////////////////////////////////////////////
	// Генерация случайных данных PKCS11
	///////////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public class Rand : RefObject, IRand
	{
		// используемый сеанс и описатель окна
		private Session session; private object window; 

		// конструктор
		public Rand(Applet token, byte[] seed, object window) 
        {
			// открыть сеанс с токеном
			session = token.OpenSession(API.CKS_RO_PUBLIC_SESSION);  
		    try { 
			    // установить стартовое значение генератора
			    if (seed != null) session.SeedRandom(seed, 0, seed.Length); 
            }
            // обработать возможную ошибку
            catch { session.Dispose(); throw; } this.window = window; 
		}
        // деструктор
        protected override void OnDispose() 
        {
            // освободить выделенные ресурсы
            session.Dispose(); base.OnDispose(); 
        } 
        // изменить окно для генератора
        public virtual IRand CreateRand(object window) 
        { 
			// изменить окно для генератора
            return CAPI.Rand.Rebind(this, window); 
        } 
		// сгенерировать случайные данные
		public virtual void Generate(byte[] bytes, int start, int len)
		{
			// сгенерировать случайные данные
			session.GenerateRandom(bytes, start, len);
		}
		// сгенерировать случайные данные
		public virtual byte[] Generate(int len)
		{
			// выделить буфер требуемого размера
			byte[] buffer = new byte[len]; 

			// сгенерировать случайные данные
			Generate(buffer, 0, len); return buffer; 
		}
		// описатель окна, связанного с генератором
		public virtual object Window { get { return window; }}	
	};
}
