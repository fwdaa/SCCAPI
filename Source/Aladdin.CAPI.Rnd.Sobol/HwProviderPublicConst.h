//---------------------------------------------------------------------------------------------------
// Copyright: (c) 1998-2002 Информзащита, Россия
//---------------------------------------------------------------------------------------------------
// $Archive: /Common/Include/HwProviderPublicConst.h $	
// $Revision: 94 $
// $Date: 23.03.05 12:24 $
// Unit:        Hw*.dll
// Author:      Денис Иванов, Андрей Робинсон
// Responsible: Андрей Робинсон
//---------------------------------------------------------------------------------------------------
// Description: Константы для работы с драйверами/библиотеками устройств аппаратной поддержки
//---------------------------------------------------------------------------------------------------
// Modification History: 
//
// 21.06.2003 * Добавлены константы SNHW_REMOVABLE_DEVICE_ID, SNHW_IDTYPE_REMOVABLE и SNHW_IDTYPE_REMOVABLE_DRIVE
//				для поддержки съёмных дисков
// 25.09.2001 * Добавлены константы SNHW_TYPE_xx_READER, призванные заменить константы SNHW_PARAM_xx_READER
// 25.09.2001 * Добавлены константы SNHW_PARAM_AUTODETECT, SNHW_PARAM_PERSONAL_CONFIG_SYS, SNHW_PARAM_RANDOM_GENERATOR,
//              SNHW_PARAM_SOFT_MODE_SUPPORTED в рамках работ по объединению с константами файла snhw.h (9x)
// 06.06.2001 * Добавлена константа SNHW_TYPE_MASK: маска для отделения типа устройства от параметров
// 06.06.2001 * Изменено значение константы SNHW_PARAM_AUTODETECT_WITH_PID (для совместимости с 9x)
// 06.06.2001 * В файл добавлен стандартный заголовок
// 27.05.2002 * Добавлены константы для TM Card PCI
//---------------------------------------------------------------------------------------------------

#ifndef __PUBLICCONST_H__
#define __PUBLICCONST_H__

#include <tchar.h>

// Это определение нужно чтобы в CPP правильно распозновались
// функции
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Имя каталога в дереве имен WindowsNT
#define SecretNetDir L"\\SecretNet" 

#ifdef UNICODE
	#define DLL_NAME L"SNetApi.dll"
#else
	#define DLL_NAME "SNetApi.dll"
#endif


//===========================================================================================
//                             К О Н С Т А Н Т Ы
//===========================================================================================

//===========================================================================================
//            Коды устройств, используемые в функции SnhwGetDeviceInfo
//===========================================================================================
#define SNHW_SNET_CARD_DEVICE_ID		0x0001			// Secret Net Card/ROM
#define SNHW_SMARTY_DEVICE_ID			0x0002			// Smarty
#define SNHW_SNTM_DEVICE_ID				0x0004			// считыватель Secret Net Touch Memory
#define SNHW_TMCOM_DEVICE_ID			0x0005			// COM-считыватель Touch Memory
#define SNHW_GCR_DEVICE_ID				0x0006			// считыватель GСR-200/400/410
#define SNHW_ASEDRIVE_DEVICE_ID			0x0007			// считыватель ASE Drive
#define SNHW_ACCORD_DEVICE_ID			0x0008			// Accord
#define SNHW_PCSC_DEVICE_ID				0x0010			// PC/SC-совместимый считыватель смарткарт
#define SNHW_FLOPPY_DEVICE_ID			0x0020			// Дисковод
#define SNHW_PROXIMITY_DEVICE_ID		0x0040			// Proximity
#define SNHW_SOBOL_DEVICE_ID			0x0080			// Электронный замок Sobol
#define SNHW_ETOKEN_DEVICE_ID			0x0009			// eToken
//пока не используются, добавлены для дальнейшего использования
#define SNHW_SNTMPCI_DEVICE_ID			0x0100			// считыватель Secret Net Touch Memory PCI
#define SNHW_REMOVABLE_DEVICE_ID		0x0200			// съёмный диск
#define SNHW_PROXIMITYPCI_DEVICE_ID		0x0300			// считыватель Proximity PCI
#define SNHW_SNTMPCI_NEW_DEVICE_ID		0x0400			// считыватель Secret Net Touch Memory PCI (новая версия)
//===========================================================================================
//       Константы, которыми задаётся тип устройства в функции SnhwGetDeviceInfo
//===========================================================================================
#define SNHW_TYPE_NO_READER				0x00000000		// у устройства нет считывателя
#define SNHW_TYPE_TM_READER				0x00000001		// устройство - считыватель Touch Memory
#define SNHW_TYPE_SMARTCARD_READER		0x00000002		// устройство - считыватель SmartCard
#define SNHW_TYPE_PROXIMITY_READER		0x00000003		// устройство - считыватель Proximity
#define SNHW_TYPE_ETOKEN_READER			0x00000004		// устройство - считыватель eToken
#define SNHW_TYPE_MASK					0x000000FF		// маска для отделения типа устройства от параметров

// Светлой памяти Денис Иванов почему-то обозвал константы по-другому.
// Следующие определения нужны для совместимости с уже написанным кодом. Для новых
// программ следует использовать константы SNHW_TYPE_xx
#define SNHW_PARAM_TM_READER			SNHW_TYPE_TM_READER
#define SNHW_PARAM_SMARTCARD_READER		SNHW_TYPE_SMARTCARD_READER
#define SNHW_PARAM_PROXIMITY_READER		SNHW_TYPE_PROXIMITY_READER
#define SNHW_PARAM_ETOKEN_READER		SNHW_TYPE_ETOKEN_READER



//===========================================================================================
//       Константы, которыми задаются параметры устройства в функции SnhwGetDeviceInfo
//===========================================================================================
#define SNHW_PARAM_NO_FAST_READY_CHECK	0x00000100		// устройство не поддерживает быструю проверку
														// наличия в нем идентификатора
#define SNHW_PARAM_READ_MEMORY			0x00000200		// устройство поддерживает чтение памяти
														// идентификатора
#define SNHW_PARAM_WRITE_MEMORY			0x00000400		// устройство поддерживает запись памяти
														// идентификатора
#define SNHW_PARAM_PARAMS_DIALOG		0x00000800		// для настройки параметров устройства нужно
														// вызвать функцию из библиотеки, которая
														// покажет диалог настройки
#define SNHW_PARAM_AUTODETECT			0x00001000		// поддерживается автоопределение параметров
														// устройства (т.е. работает функция SnhwDetectParams)
#define SNHW_PARAM_AUTODETECT_WITH_PID	0x00002000		// для автонастройки параметров устройства
														// необходимо предъявить персональный идентификатор
#define SNHW_PARAM_PERSONAL_CONFIG_SYS	0x00004000		// устройство поддерживает работу с персональным
														// файлом config.sys
#define SNHW_PARAM_RANDOM_GENERATOR		0x00008000		// у устройства есть датчик случайных чисел
#define SNHW_PARAM_SOFT_MODE_SUPPORTED	0x00010000		// устройство поддерживает идентификацию в "мягком режиме"


//===========================================================================================
//          Константы, которыми задается тип персонального идентификатора
//===========================================================================================
#define SNHW_IDTYPE_FLOPPY				0x00000000	// есть память и ее можно записывать
#define SNHW_IDTYPE_PROXIMITY			0x01000000	// карта Proximity
#define SNHW_IDTYPE_ETOKEN				0x02000000  // eToken
#define SNHW_IDTYPE_REMOVABLE			0x04000000  // съемный диск
#define SNHW_IDTYPE_TOUCHMEMORY			0x80000000	// таблетка touch memory
#define SNHW_IDTYPE_SMARTCARD			0x40000000	// смарткарта
#define SNHW_IDTYPE_MEM_READ			0x20000000	// есть память и ее можно читать
#define SNHW_IDTYPE_MEM_WRITE			0x10000000	// есть память и ее можно записывать


// макрос для определения общего типа идентификатора по конкретному типу
#define GET_PID_FAMILY_TYPE( dwPidType )	( dwPidType & 0xCF000000 )


// таблетка 1990
#define SNHW_IDTYPE_DS1990				( 0x01 | SNHW_IDTYPE_TOUCHMEMORY )
// таблетка 1991
#define SNHW_IDTYPE_DS1991				( 0x02 | SNHW_IDTYPE_TOUCHMEMORY )
// таблетка 1992
#define SNHW_IDTYPE_DS1992				( 0x03 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// таблетка 1993
#define SNHW_IDTYPE_DS1993				( 0x04 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// таблетка 1994
#define SNHW_IDTYPE_DS1994				( 0x05 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// таблетка 1995
#define SNHW_IDTYPE_DS1995				( 0x06 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// таблетка 1996
#define SNHW_IDTYPE_DS1996				( 0x07 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// смарткарта Gemplus PCOS
#define SNHW_IDTYPE_PCOS				( 0x08 | SNHW_IDTYPE_SMARTCARD | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )

// смарткарта Gemplus MPCOS-EMV
#define SNHW_IDTYPE_MPCOSEMV			( 0x09 | SNHW_IDTYPE_SMARTCARD )

// Proximity
#define SNHW_IDTYPE_PROXIMITY_CARD		( 0x10 | SNHW_IDTYPE_PROXIMITY )

// дискета
#define SNHW_IDTYPE_FLOPPY_DISK			( 0x00 | SNHW_IDTYPE_FLOPPY )

// eToken R2
#define SNHW_IDTYPE_ETOKEN_R2			( 0x0A | SNHW_IDTYPE_ETOKEN | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// съемный диск
#define SNHW_IDTYPE_REMOVABLE_DRIVE		( 0x0B | SNHW_IDTYPE_REMOVABLE | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )


//===========================================================================================
// Информация, специфичная для разных идентификаторов
//===========================================================================================
#define ETOKEN_DEFAULT_PIN	_T( "1234567890" )


//===========================================================================================
//         Константы, которыми задается код строки в функции SnhwGetString
//===========================================================================================
#define SNHW_STRING_INSERT				0x00000001
#define SNHW_LANGUAGE_ENGLISH			0x01000000
#define SNHW_LANGUAGE_RUSSIAN			0x02000000
#define SNHW_LANGUAGE_MASK				0xFF000000
#define SNHW_LANGUAGE_MAX				( SNHW_LANGUAGE_RUSSIAN | SNHW_LANGUAGE_ENGLISH )

//===========================================================================================
// Строковые константы имен inf-файлов
//===========================================================================================
//максимальная длина имени файла с расширением
#define MAX_INF_FILE_LEN	14
#define MAX_HW_ID_LEN		40

#define SNTM_INF_FILE		_T("TmCard.inf")
#define SNTM_HW_ID			_T("*SnTm")
#define SNTMPCI_INF_FILE	_T("TmCardPci.inf")
#define SNTMPCI_HW_ID		_T("PCI\\VEN_10EE&DEV_2002&SUBSYS_000910EE")
#define SNTMPCI_HW_ID_NEW	_T("PCI\\VEN_10EE&DEV_2002&SUBSYS_000210EE")
#define TMCOM_INF_FILE		_T("TmComm.inf")
#define TMCOM_HW_ID			_T("*TmComm")
#define PCSC_INF_FILE		_T("PcSc.inf")
#define PCSC_HW_ID			_T("*PcSc")
#define PRXMPCI_INF_FILE	_T("PrxmPci.inf")
#define PROXIMITY_INF_FILE	_T("proxim.inf")
#define PROXIMITY_HW_ID		_T("*Proximity")
#define ETOKEN_INF_FILE		_T("eToken.inf")
#define ETOKEN_HW_ID		_T("*EToken")

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __PUBLICCONST_H__