using System;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Генератор случайных данных
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public sealed class Rand : RefObject, IRand
	{
        // объект и функция генерации данных
        private IDisposable obj; private Action<Byte[]> generator; 
        
        // описатель окна и дополнительный генератор
        private object window; private IRand rand; 

        // создать сериализуемый генератор на основе другого генератора
        public static IRand Create(IRand rand, Type type)
        {
            // получить описание конструктора
            ConstructorInfo constructor = type.GetConstructor(new Type[] { typeof(IRand) }); 

            // проверить наличие конструктора
            if (constructor == null) throw new InvalidOperationException(); 

            // создать генератор на основе другого генератора
            try { return (IRand)constructor.Invoke(new object[] { rand });  }

            // обработать возможное исключение
            catch (TargetInvocationException e) { throw e.InnerException; }
        }
        // изменить окно для генератора
        public static IRand Rebind(IRand rand, object window) 
        { 
            // изменить окно для генератора
            return new Rand(rand, window); 
        }
		// конструктор
        private Rand(IRand rand, object window)
        {
            // инициализировать переменные
            this.obj = null; this.generator = null; 

            // сохранить дополнительный генератор
            this.window = window; this.rand = RefObject.AddRef(rand); 
        }

		// конструктор
        public Rand(object window) : this(RNGCryptoServiceProvider.Create(), window) {}
        // конструктор
        public Rand(System.Security.Cryptography.RandomNumberGenerator random, object window) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.GetBytes; 

            // сохранить переданные параметры
            this.window = window; this.rand = null; 
        }
        // конструктор
        public Rand(System.Security.Cryptography.RandomNumberGenerator random, IRand rand) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.GetBytes; 
            
            // сохранить дополнительный генератор
            this.window = rand.Window; this.rand = RefObject.AddRef(rand); 
        }
        // конструктор
        public Rand(System.Random random, object window) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.NextBytes; 

            // сохранить переданные параметры
            this.window = window; this.rand = null; 
        }
        // конструктор
        public Rand(System.Random random, IRand rand) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.NextBytes; 
            
            // сохранить дополнительный генератор
            this.window = rand.Window; this.rand = RefObject.AddRef(rand); 
        }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            if (obj != null) obj.Dispose(); 
            
            // освободить выделенные ресурсы
            RefObject.Release(rand); base.OnDispose(); 
        }
        // описатель окна
        public object Window { get { return window; }}

		// сгенерировать случайные данные
		public void Generate(byte[] data, int dataOff, int dataLen)
		{
			// сгенерировать случайные данные
            byte[] buffer = Generate(dataLen); 

			// скопировать сгенерированные данные
			Array.Copy(buffer, 0, data, dataOff, dataLen); 
		}
		// сгенерировать случайные данные
		public byte[] Generate(int dataLen)
		{
			// выделить буфер для данных
            byte[] buffer = new byte[dataLen]; 
            
			// сгенерировать случайные данные
            if (generator != null) generator(buffer); 

            // выделить дополнительный буфер данных
            if (rand != null) { byte[] buffer2 = new byte[dataLen];

                // сгенерировать дополнительные данные
                rand.Generate(buffer2, 0, dataLen); 

                // выполнить сложение данных
                for (int i = 0; i < dataLen; i++) buffer[i] ^= buffer2[i]; 
            }
            return buffer; 
		}
	}
}
