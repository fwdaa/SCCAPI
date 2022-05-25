using System;
using System.Collections.Generic;

namespace Aladdin.CAPI.PKCS12
{
	///////////////////////////////////////////////////////////////////////////
	// Провайдер контейнеров PKCS12
	///////////////////////////////////////////////////////////////////////////
	public class CryptoProvider : Software.CryptoProvider
	{
        // парольная защита
        private PBE.IPBECultureFactory cultureFactory; 

        // провайдер только для чтения
        public static CryptoProvider Readonly(IEnumerable<Factory> factories, IRand rand)
        {
            // вернуть провайдер
            return new CryptoProvider(factories, rand); 
        }
        // провайдер только для чтения
        public static CryptoProvider Readonly(IEnumerable<Factory> factories)
        {
            // указать генератор случайных данных
            using (IRand rand = new Rand(null))
            { 
                // вернуть провайдер только для чтения
                return Readonly(factories, rand); 
            }
        }
		// конструктор 
		public CryptoProvider(ExecutionContext executionContext) 

            // сохранить переданные параметры
            : base(executionContext, "PKCS12", new string[] { "p12", "pfx" }) 
        {
            // сохранить парольную защиту
            this.cultureFactory = executionContext; 
        }
		// конструктор
		public CryptoProvider(IEnumerable<Factory> factories, IRandFactory randFactory) 

            // сохранить переданные параметры
            : base(factories, randFactory, "PKCS12", new string[] { "p12", "pfx" }) 
        {
            // сохранить парольную защиту
            this.cultureFactory = null; 
        }
		///////////////////////////////////////////////////////////////////////
        // Генерация случайных данных
		///////////////////////////////////////////////////////////////////////
        
        // фабрика генераторов случайных данных
        public override IRandFactory CreateRandFactory(SecurityObject scope, bool strong) 
        { 
            // проверить наличие контекста выполнения
            if (cultureFactory is IRandFactory) return RefObject.AddRef(this); 

            // вызвать базовую функцию
            return base.CreateRandFactory(scope, strong); 
        }
        // создать генератор случайных данных
        public override IRand CreateRand(object window) 
        { 
            // проверить наличие контекста выполнения
            if (cultureFactory is IRandFactory) 
            {
                // создать генератор случайных данных
                return ((IRandFactory)cultureFactory).CreateRand(window); 
            }
            // вызвать базовую функцию
            return base.CreateRand(window); 
        } 
		///////////////////////////////////////////////////////////////////////
		// Управление контейнерами
		///////////////////////////////////////////////////////////////////////
        public override Software.Container CreateContainer(IRand rand, 
            Software.ContainerStore store, Software.ContainerStream stream, 
            string password, string keyOID)
		{
            // указать культуру по умолчанию
            if (password == null || cultureFactory == null) throw new InvalidOperationException(); 

            // получить парольную защиту
            PBE.PBECulture culture = cultureFactory.GetPBECulture(rand.Window, keyOID); 

            // проверить поддержку защиты
            if (culture == null) throw new NotSupportedException(); 

		    // создать пустое содержимое
		    ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe authenticatedSafe = 
			    new ASN1.ISO.PKCS.PKCS12.AuthenticatedSafe();

            // получить параметры шифрования по паролю
            PBE.PBEParameters pbeParameters = culture.PBEParameters; 

        	// выделить память для salt-значения
			byte[] salt = new byte[pbeParameters.PBMSaltLength]; 

   	        // сгенерировать salt-значение
            rand.Generate(salt, 0, salt.Length); 

            // создать пустой контейнер
            ASN1.ISO.PKCS.PKCS12.PFX pfx = Pfx.CreateAuthenticatedContainer(
                this, authenticatedSafe, culture.HashAlgorithm(rand), 
                salt, pbeParameters.PBMIterations, password
            );
            // создать объект контейнера
            using (Container container = new Container(
                cultureFactory, rand, store, stream, pfx))
            { 
                // установить пароль контейнера
                container.Password = password; 
                        
                // вернуть объект контейнера
                return RefObject.AddRef(container); 
            }
		}
	    public override Software.Container OpenContainer(
            Software.ContainerStore store, Software.ContainerStream stream)
	    {
		    // раскодировать данные
		    ASN1.ISO.PKCS.PKCS12.PFX pfx = new ASN1.ISO.PKCS.PKCS12.PFX(
                ASN1.Encodable.Decode(stream.Read())
            );
            // указать генератор случайных данных
            using (IRand rand = CreateRand(null))
            { 
                // вернуть объект контейнера
                return new Container(cultureFactory, rand, store, stream, pfx); 
            }
	    }
	}
}
