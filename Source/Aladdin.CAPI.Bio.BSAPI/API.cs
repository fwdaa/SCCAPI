using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;

namespace Aladdin.CAPI.Bio.BSAPI
{
    public static class API
    {
		///////////////////////////////////////////////////////////////////////
		// Инициализировать библиотеку / освободить ее ресурсы
		///////////////////////////////////////////////////////////////////////
        [Flags] public enum InitFlags { // режим инициализации библиотеки
            ServiceNT			= 0x1,  // режим совместимый с Windows NT сервисами
			ForceLocalSensor	= 0x2,  // игнорирование удаленных сеансов и использование локальных
			ForceRemoteSensor	= 0x4   // использование удаленных сеансов вместо локальных
        }
		// инициализировать библиотеку
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public static void InitiaizeEx(InitFlags flags)
		{
			// инициализировать библиотеку
			Int32 status = NativeMethods.ABSInitializeEx(flags); 

			// проверить отсутствие ошибок
			if (status != 0 && status != -5003) throw new Exception(status);  
		}
		// инициализировать библиотеку
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public static void Initiaize()
		{
			// инициализировать библиотеку
			Int32 status = NativeMethods.ABSInitialize(); 

			// проверить отсутствие ошибок
			if (status != 0 && status != -5003) throw new Exception(status);  
		}
		// освободить ресурсы библиотеки
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public static void Terminate() { NativeMethods.ABSTerminate(); }

		///////////////////////////////////////////////////////////////////////
		// Перечислить биометрические устройства
		///////////////////////////////////////////////////////////////////////
        [SecuritySafeCritical]
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
		public static String[] EnumerateDevices(String dsn)
		{
			// указать тип структуры
			Type itemType = typeof(NativeMethods.DEVICE_LIST_ITEM); IntPtr pDeviceList;  

			// определить размер структуры
			Int32 itemSize = Marshal.SizeOf(itemType); 

			// перечислить биометрические устройства
			Int32 status = NativeMethods.ABSEnumerateDevices(dsn, out pDeviceList); 

			// проверить отсутствие ошибок
			if (status != 0) throw new Exception(status);  
            
			// определить число полученных устройств
			Int32 deviceCount = Marshal.ReadInt32(pDeviceList);

			// выделить список структур
			String[] listDevices = new String[deviceCount]; 

			// перейти на описание первого устройства
			IntPtr pDevice = new IntPtr(pDeviceList.ToInt64() + sizeof(Int32));

			// для всех устройств
			for (int i = 0; i < deviceCount; i++)
			{
				// извлечь описание структуры
				NativeMethods.DEVICE_LIST_ITEM item = 
                    (NativeMethods.DEVICE_LIST_ITEM)
                        Marshal.PtrToStructure(pDevice, itemType);

				// сохранить имя устройства
				listDevices[i] = item.DsnSubString; 

				// перейти на следующую структуру
				pDevice = new IntPtr(pDeviceList.ToInt64() + itemSize); 
			}
			// освободить выделенную память
			NativeMethods.ABSFree(pDeviceList); return listDevices; 
		}
    }
}
