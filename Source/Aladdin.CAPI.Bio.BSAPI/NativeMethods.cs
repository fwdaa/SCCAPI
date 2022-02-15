using System;
using System.Security;
using System.Runtime.InteropServices;

namespace Aladdin.CAPI.Bio.BSAPI
{
    internal static class NativeMethods
    {
		///////////////////////////////////////////////////////////////////////
		// Инициализировать библиотеку
		///////////////////////////////////////////////////////////////////////
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern Int32 ABSInitializeEx(
            [MarshalAs(UnmanagedType.U4)] API.InitFlags dwFlags
        );
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]        
        internal static extern Int32 ABSInitialize();
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern Int32 ABSTerminate();

		///////////////////////////////////////////////////////////////////////
		// Освобождение выделенной памяти
		///////////////////////////////////////////////////////////////////////
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern void ABSFree(IntPtr ptr);

		///////////////////////////////////////////////////////////////////////
		// Перечислить биометрические устройства
		///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        internal struct DEVICE_LIST_ITEM {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public String DsnSubString;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public Byte[] reserved;	  
        };
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Ansi, BestFitMapping = false)]
        internal static extern Int32 ABSEnumerateDevices(
            String pszEnumDsn,	                        // имя интерфейса соединения
			out IntPtr pDeviceList                      // список описания устройств
        );
		///////////////////////////////////////////////////////////////////////
		// Создать/закрыть соединение с биометрическим устройством
		///////////////////////////////////////////////////////////////////////
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi, 
            CharSet = CharSet.Ansi, BestFitMapping = false)]
        internal static extern Int32 ABSOpen(
            String DsnSubString,	                    // имя устройства
			out UInt32 phConnection	                    // описатель соединения
        );
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern Int32 ABSClose(UInt32 hConnection);

		///////////////////////////////////////////////////////////////////////
		// Перечислить поддерживаемые форматы изображения
		///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential)]
        internal struct IMAGE_HEADER {	                // заголовок изображения
            public UInt32 Width;			            // ширина изображения в пикселах
            public UInt32 Height; 			            // высота изображения в пикселах
            public UInt32 ColorCount;		            // максимальное число цветов изображения
            public UInt32 HorizontalDPI;	            // горизонтальное разрешение (в точках на дюйм)
            public UInt32 VerticalDPI;                  // вертикальное разрешение   (в точках на дюйм)
        }    								            // изображение (цвета всех пикселов, Width * Height байт)
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern Int32 ABSListImageFormats(
            UInt32 hConnection,				            // описатель соединения
            out UInt32 dwCount,				            // число поддерживаемых форматов
            out IntPtr pImageFormatList,	            // спосок поддерживаемых форматов
            UInt32 dwFlags					            // зарезервировано
        );
 		///////////////////////////////////////////////////////////////////////
		// Отменить выполняемую операцию
		///////////////////////////////////////////////////////////////////////
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern Int32 ABSCancelOperation(
            UInt32 hConnection,                         // описатель соединения
            UInt32 dwOperationID                        // идентификатор операции
        );
 		///////////////////////////////////////////////////////////////////////
		// Качество биометрического отпечатка
		///////////////////////////////////////////////////////////////////////
        [Flags] internal enum SWIPE_FLAGS {	            // свойства отпечатка
            TooFast				= 0x01,                 // отпечаток проведен слишком быстро
            TooSkewed			= 0x02,                 // отпечаток слишком перекошен
            BackwardsMovement	= 0x04,                 // неправильное направление оптечатка
            JointDetected		= 0x08,                 // обнаружено совмещение отпечатков
            TooShort			= 0x10,                 // отпечаток слишком малый
        }
 		///////////////////////////////////////////////////////////////////////
        // Описание параметров навигации
 		///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential)]
		internal struct NavigationData {
			Int32 DeltaX;			                    // изменение горизонтального положения  
			Int32 DeltaY;			                    // изменение вертикального положения
			Int32 FingerPresent;	                    // признак удержания пальца
		}		
 		///////////////////////////////////////////////////////////////////////
		// Информация отпечатка
		///////////////////////////////////////////////////////////////////////
        [StructLayout(LayoutKind.Sequential)]
        internal struct SWIPE_INFO {			            
            public UInt32       Version; 	            // версия структуры (текущее значение = 1)
            public UInt16       Height; 	            // высота изображения в пикселах
            public Byte         ReconstructionScore;    // качество реконструкции в процентах
            public Byte         ImageScore; 	        // качество изображения в процентах
            public ImageQuality Quality; 	            // качество отпечатка
            public SWIPE_FLAGS  Flags;                  // свойства отпечатка
            public UInt32       BackgroundColor;        // фоновый цвет отпечатка
        };
 		///////////////////////////////////////////////////////////////////////
		// Назначение снятия отпечатка
		///////////////////////////////////////////////////////////////////////
        internal enum Purpose : uint {	
            Undefined	= 0,	    // назначение неизвестно
            Verify		= 1,	    // назначение проверки совпадения 
            Enroll		= 3		    // назначение для регистрации образца
        };
 		///////////////////////////////////////////////////////////////////////
		// Снятие отпечатка
		///////////////////////////////////////////////////////////////////////
        internal delegate void CALLBACK(ref OPERATION operation, Int32 msgID, IntPtr msgData);

        [StructLayout(LayoutKind.Sequential)]
        internal struct OPERATION {                     // описание параметров операции
            public UInt32			OperationID;        // уникальный идентификатор операции
            public IntPtr			Context;            // дополнительные данные для функции обратного вызова
            public CALLBACK 		Callback;           // указатель на функцию обратного вызова
            public Int32			Timeout; 	        // тайм-аут ожидания активности пользователя в миллисекундах
            public NotificationMode	Flags;		        // режим выполнения операции
        };
        [DllImport("bsapi.dll", CallingConvention = CallingConvention.Winapi)]
        internal static extern Int32 ABSGrabImage(
            UInt32          hConnection,                // описатель соединения  
            ref OPERATION   pOperation,                 // параметры операции
            Purpose         dwPurpose,                  // назначение снимаемого отпечатка
            ref ImageFormat pImageFormat,               // формат изображения
            out IntPtr      pImage,                     // полученное изображение
            out SWIPE_INFO  pSwipeInfo,                 // информация отпечатка  
            IntPtr          pReserved,                  // зарезервировано
            UInt32          dwFlags                     // зарезервировано     
        );
    }
}
