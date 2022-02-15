//---------------------------------------------------------------------------------------------------
// Copyright: (c) 1998-2002 ������������, ������
//---------------------------------------------------------------------------------------------------
// $Archive: /Common/Include/HwProviderPublicConst.h $	
// $Revision: 94 $
// $Date: 23.03.05 12:24 $
// Unit:        Hw*.dll
// Author:      ����� ������, ������ ��������
// Responsible: ������ ��������
//---------------------------------------------------------------------------------------------------
// Description: ��������� ��� ������ � ����������/������������ ��������� ���������� ���������
//---------------------------------------------------------------------------------------------------
// Modification History: 
//
// 21.06.2003 * ��������� ��������� SNHW_REMOVABLE_DEVICE_ID, SNHW_IDTYPE_REMOVABLE � SNHW_IDTYPE_REMOVABLE_DRIVE
//				��� ��������� ������� ������
// 25.09.2001 * ��������� ��������� SNHW_TYPE_xx_READER, ���������� �������� ��������� SNHW_PARAM_xx_READER
// 25.09.2001 * ��������� ��������� SNHW_PARAM_AUTODETECT, SNHW_PARAM_PERSONAL_CONFIG_SYS, SNHW_PARAM_RANDOM_GENERATOR,
//              SNHW_PARAM_SOFT_MODE_SUPPORTED � ������ ����� �� ����������� � ����������� ����� snhw.h (9x)
// 06.06.2001 * ��������� ��������� SNHW_TYPE_MASK: ����� ��� ��������� ���� ���������� �� ����������
// 06.06.2001 * �������� �������� ��������� SNHW_PARAM_AUTODETECT_WITH_PID (��� ������������� � 9x)
// 06.06.2001 * � ���� �������� ����������� ���������
// 27.05.2002 * ��������� ��������� ��� TM Card PCI
//---------------------------------------------------------------------------------------------------

#ifndef __PUBLICCONST_H__
#define __PUBLICCONST_H__

#include <tchar.h>

// ��� ����������� ����� ����� � CPP ��������� ��������������
// �������
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// ��� �������� � ������ ���� WindowsNT
#define SecretNetDir L"\\SecretNet" 

#ifdef UNICODE
	#define DLL_NAME L"SNetApi.dll"
#else
	#define DLL_NAME "SNetApi.dll"
#endif


//===========================================================================================
//                             � � � � � � � � �
//===========================================================================================

//===========================================================================================
//            ���� ���������, ������������ � ������� SnhwGetDeviceInfo
//===========================================================================================
#define SNHW_SNET_CARD_DEVICE_ID		0x0001			// Secret Net Card/ROM
#define SNHW_SMARTY_DEVICE_ID			0x0002			// Smarty
#define SNHW_SNTM_DEVICE_ID				0x0004			// ����������� Secret Net Touch Memory
#define SNHW_TMCOM_DEVICE_ID			0x0005			// COM-����������� Touch Memory
#define SNHW_GCR_DEVICE_ID				0x0006			// ����������� G�R-200/400/410
#define SNHW_ASEDRIVE_DEVICE_ID			0x0007			// ����������� ASE Drive
#define SNHW_ACCORD_DEVICE_ID			0x0008			// Accord
#define SNHW_PCSC_DEVICE_ID				0x0010			// PC/SC-����������� ����������� ���������
#define SNHW_FLOPPY_DEVICE_ID			0x0020			// ��������
#define SNHW_PROXIMITY_DEVICE_ID		0x0040			// Proximity
#define SNHW_SOBOL_DEVICE_ID			0x0080			// ����������� ����� Sobol
#define SNHW_ETOKEN_DEVICE_ID			0x0009			// eToken
//���� �� ������������, ��������� ��� ����������� �������������
#define SNHW_SNTMPCI_DEVICE_ID			0x0100			// ����������� Secret Net Touch Memory PCI
#define SNHW_REMOVABLE_DEVICE_ID		0x0200			// ������� ����
#define SNHW_PROXIMITYPCI_DEVICE_ID		0x0300			// ����������� Proximity PCI
#define SNHW_SNTMPCI_NEW_DEVICE_ID		0x0400			// ����������� Secret Net Touch Memory PCI (����� ������)
//===========================================================================================
//       ���������, �������� ������� ��� ���������� � ������� SnhwGetDeviceInfo
//===========================================================================================
#define SNHW_TYPE_NO_READER				0x00000000		// � ���������� ��� �����������
#define SNHW_TYPE_TM_READER				0x00000001		// ���������� - ����������� Touch Memory
#define SNHW_TYPE_SMARTCARD_READER		0x00000002		// ���������� - ����������� SmartCard
#define SNHW_TYPE_PROXIMITY_READER		0x00000003		// ���������� - ����������� Proximity
#define SNHW_TYPE_ETOKEN_READER			0x00000004		// ���������� - ����������� eToken
#define SNHW_TYPE_MASK					0x000000FF		// ����� ��� ��������� ���� ���������� �� ����������

// ������� ������ ����� ������ ������-�� ������� ��������� ��-�������.
// ��������� ����������� ����� ��� ������������� � ��� ���������� �����. ��� �����
// �������� ������� ������������ ��������� SNHW_TYPE_xx
#define SNHW_PARAM_TM_READER			SNHW_TYPE_TM_READER
#define SNHW_PARAM_SMARTCARD_READER		SNHW_TYPE_SMARTCARD_READER
#define SNHW_PARAM_PROXIMITY_READER		SNHW_TYPE_PROXIMITY_READER
#define SNHW_PARAM_ETOKEN_READER		SNHW_TYPE_ETOKEN_READER



//===========================================================================================
//       ���������, �������� �������� ��������� ���������� � ������� SnhwGetDeviceInfo
//===========================================================================================
#define SNHW_PARAM_NO_FAST_READY_CHECK	0x00000100		// ���������� �� ������������ ������� ��������
														// ������� � ��� ��������������
#define SNHW_PARAM_READ_MEMORY			0x00000200		// ���������� ������������ ������ ������
														// ��������������
#define SNHW_PARAM_WRITE_MEMORY			0x00000400		// ���������� ������������ ������ ������
														// ��������������
#define SNHW_PARAM_PARAMS_DIALOG		0x00000800		// ��� ��������� ���������� ���������� �����
														// ������� ������� �� ����������, �������
														// ������� ������ ���������
#define SNHW_PARAM_AUTODETECT			0x00001000		// �������������� ��������������� ����������
														// ���������� (�.�. �������� ������� SnhwDetectParams)
#define SNHW_PARAM_AUTODETECT_WITH_PID	0x00002000		// ��� ������������� ���������� ����������
														// ���������� ���������� ������������ �������������
#define SNHW_PARAM_PERSONAL_CONFIG_SYS	0x00004000		// ���������� ������������ ������ � ������������
														// ������ config.sys
#define SNHW_PARAM_RANDOM_GENERATOR		0x00008000		// � ���������� ���� ������ ��������� �����
#define SNHW_PARAM_SOFT_MODE_SUPPORTED	0x00010000		// ���������� ������������ ������������� � "������ ������"


//===========================================================================================
//          ���������, �������� �������� ��� ������������� ��������������
//===========================================================================================
#define SNHW_IDTYPE_FLOPPY				0x00000000	// ���� ������ � �� ����� ����������
#define SNHW_IDTYPE_PROXIMITY			0x01000000	// ����� Proximity
#define SNHW_IDTYPE_ETOKEN				0x02000000  // eToken
#define SNHW_IDTYPE_REMOVABLE			0x04000000  // ������� ����
#define SNHW_IDTYPE_TOUCHMEMORY			0x80000000	// �������� touch memory
#define SNHW_IDTYPE_SMARTCARD			0x40000000	// ����������
#define SNHW_IDTYPE_MEM_READ			0x20000000	// ���� ������ � �� ����� ������
#define SNHW_IDTYPE_MEM_WRITE			0x10000000	// ���� ������ � �� ����� ����������


// ������ ��� ����������� ������ ���� �������������� �� ����������� ����
#define GET_PID_FAMILY_TYPE( dwPidType )	( dwPidType & 0xCF000000 )


// �������� 1990
#define SNHW_IDTYPE_DS1990				( 0x01 | SNHW_IDTYPE_TOUCHMEMORY )
// �������� 1991
#define SNHW_IDTYPE_DS1991				( 0x02 | SNHW_IDTYPE_TOUCHMEMORY )
// �������� 1992
#define SNHW_IDTYPE_DS1992				( 0x03 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// �������� 1993
#define SNHW_IDTYPE_DS1993				( 0x04 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// �������� 1994
#define SNHW_IDTYPE_DS1994				( 0x05 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// �������� 1995
#define SNHW_IDTYPE_DS1995				( 0x06 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// �������� 1996
#define SNHW_IDTYPE_DS1996				( 0x07 | SNHW_IDTYPE_TOUCHMEMORY | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// ���������� Gemplus PCOS
#define SNHW_IDTYPE_PCOS				( 0x08 | SNHW_IDTYPE_SMARTCARD | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )

// ���������� Gemplus MPCOS-EMV
#define SNHW_IDTYPE_MPCOSEMV			( 0x09 | SNHW_IDTYPE_SMARTCARD )

// Proximity
#define SNHW_IDTYPE_PROXIMITY_CARD		( 0x10 | SNHW_IDTYPE_PROXIMITY )

// �������
#define SNHW_IDTYPE_FLOPPY_DISK			( 0x00 | SNHW_IDTYPE_FLOPPY )

// eToken R2
#define SNHW_IDTYPE_ETOKEN_R2			( 0x0A | SNHW_IDTYPE_ETOKEN | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )
// ������� ����
#define SNHW_IDTYPE_REMOVABLE_DRIVE		( 0x0B | SNHW_IDTYPE_REMOVABLE | \
										SNHW_IDTYPE_MEM_READ | SNHW_IDTYPE_MEM_WRITE )


//===========================================================================================
// ����������, ����������� ��� ������ ���������������
//===========================================================================================
#define ETOKEN_DEFAULT_PIN	_T( "1234567890" )


//===========================================================================================
//         ���������, �������� �������� ��� ������ � ������� SnhwGetString
//===========================================================================================
#define SNHW_STRING_INSERT				0x00000001
#define SNHW_LANGUAGE_ENGLISH			0x01000000
#define SNHW_LANGUAGE_RUSSIAN			0x02000000
#define SNHW_LANGUAGE_MASK				0xFF000000
#define SNHW_LANGUAGE_MAX				( SNHW_LANGUAGE_RUSSIAN | SNHW_LANGUAGE_ENGLISH )

//===========================================================================================
// ��������� ��������� ���� inf-������
//===========================================================================================
//������������ ����� ����� ����� � �����������
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