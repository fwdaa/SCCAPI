/****************************************************************************
*
* enroll3.c
*
*
* Description:
*  This simple console example provides the functional framework necessary
*  for the enrollment of fingerprints to be used with Precise
*  Match-On-Card(TM) technology. This example follows the recommended
*  procedures described in the Precise BioMatch(TM) Flex H User Manual.
*
***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pb_flex_h.h"

/****************************************************************************
* Defines
****************************************************************************/
#define MINIMUM_QUALITY     75 /* 51 is the lowest possible value. For     */
                               /* higher enrollment quality, set a higher  */
                               /* value. */
#define APDU_DATA_SIZE      240

/****************************************************************************
* Global variables
****************************************************************************/
static SCARDCONTEXT context;

/****************************************************************************
* Prototype definitions
****************************************************************************/
static void 
print_error_reason(int ret);

static int 
store_template(unsigned char *biometric_header,
               int            biometric_header_size,
               unsigned char *reference_data,
               int            reference_data_size);

static void 
capture_image_callback(int  token,
                       void *context);

static void 
no_finger_callback(int  token,
                   void *context);

static SCARDHANDLE 
connect_to_card(void);

/****************************************************************************
* Main
****************************************************************************/
int main_enrol(void)
{
    int				ret, selection= -1, i, image_quality = 0;
    int             finger_present = 1, validated;
    unsigned char  *biometric_header;
    unsigned char  *reference_data;
    int  			biometric_header_size;
    int 			reference_data_size;
    int				nof_readers;
    char    	   *reader_list = NULL;
    char           *reader;
    pb_image_t     *image = NULL;
    char            stdin_string[2];


    printf("MoC enrollment example 3\n");
    printf("------------------------\n\n");

    /* Initialization */
    ret = pb_initialize();
    if (ret != PB_EOK)
    {
        fprintf(stderr, "INITIALIZE::");
        print_error_reason(ret);
        return PB_EFATAL;
    }

    /* List available readers */
    ret = pb_list_readers(&reader_list, &nof_readers);

    if (ret != PB_EOK)
    {
        fprintf(stderr, "LIST_READERS::");
        print_error_reason(ret);
        pb_release();
        return PB_EFATAL;
    }

    if (nof_readers == 0)
    {
        printf("No readers are connected to the computer.\n");
        pb_free(reader_list);
        pb_release();
        return PB_EOK;
    }

    reader = reader_list;
    
    if (nof_readers > 1) 
    {
        printf("Found %d readers.\n", nof_readers);
    }
    else 
    {
        printf("Found %d reader.\n", nof_readers);
    }

    for (i = 0; i < nof_readers; i++) 
    {
        printf("Reader %d: %s\n", i + 1, reader);
        reader = reader + strlen(reader) + 1;
    }

    /* Select reader */
    while (selection < 0 || selection > nof_readers) 
    {
        printf("Choose reader (number) or exit with 0: ");
        fgets(stdin_string, 2, stdin);
        selection = stdin_string[0] - 48; /* ASCII to int */
    }

    if (selection) 
    {
        reader = reader_list;
        for (i = 1; i < selection; i++) 
        {
            reader = reader + strlen(reader) + 1;
        }

        /* Capture image with sufficient quality.  
           pb_capture_image will return an image with quality 51 or higher. */
        while (image_quality < MINIMUM_QUALITY) 
        {
            ret = pb_capture_image(reader, 
                                   PB_TIMEOUT_FOREVER, 
                                   &image, 
                                   capture_image_callback, 
                                   NULL);
            if (ret != PB_EOK) 
            {
                fprintf(stderr, "CAPTURE_IMAGE::");
                print_error_reason(ret);
                pb_free(reader_list);
                pb_release();
                return PB_EFATAL;
            }
            
            /* We only want the quality. */
            ret = pb_finger_status(image, &image_quality, NULL, NULL);
            if (ret != PB_EOK) 
            {
                fprintf(stderr, "FINGER_STATUS::");
                print_error_reason(ret);
                pb_free_image(image);
                pb_free(reader_list);
                pb_release();
                return PB_EFATAL;
            }
        }

        /* Tell user to lift finger */
        printf("Please lift your finger...\n");
        ret = pb_wait_for_no_finger(reader, 
                                    PB_TIMEOUT_FOREVER, 
                                    no_finger_callback, 
                                    NULL);
        if (ret != PB_EOK) 
        {
            fprintf(stderr, "WAIT_FINGER::");
            print_error_reason(ret);
            pb_free_image(image);
            pb_free(reader_list);
            pb_release();
            return PB_EFATAL;
        }

        /* Create template, FAR = 1/10000 */
        ret = pb_fh_create_enrollment_data(image,
                                           0x7fffffff/10000,
                                           &reference_data, 
                                           &reference_data_size, 
                                           &biometric_header, 
                                           &biometric_header_size);

        pb_free_image(image);
        image = NULL;
        image_quality = 0;

        if (ret != PB_EOK) 
        {
            fprintf(stderr, "CREATE_REFERENCE_DATA::");
            print_error_reason(ret);
            pb_free(reader_list);
            pb_release();
            return PB_EFATAL;
        }

        printf("\nEnrollment data created. Please put finger on sensor again to validate\n");

        /* Capture image for validation */
        ret = pb_capture_image(reader, 
                               PB_TIMEOUT_FOREVER, 
                               &image, 
                               capture_image_callback, 
                               NULL);
        if (ret != PB_EOK) {
            fprintf(stderr, "CAPTURE_IMAGE::");
            print_error_reason(ret);
            pb_free(reader_list);
            pb_release();
            return PB_EFATAL;
        }
                
        /* Validate the created template with the second image */
        ret = pb_fh_validate_template(image, 
                                      biometric_header, 
                                      biometric_header_size, 
                                      reference_data, 
                                      reference_data_size, 
                                      &validated);

        pb_free_image(image);

        if (ret != PB_EOK) 
        {
            fprintf(stderr, "VALIDATE_TEMPLATE::");
            print_error_reason(ret);
            pb_free(reader_list);
            pb_free(biometric_header);
            pb_free(reference_data);
            pb_release();
            return PB_EFATAL;
        }
        
        if (validated == PB_TRUE) 
        {
            printf("Reference data successfully validated!\n");

            ret = store_template(biometric_header, biometric_header_size,
                                 reference_data, reference_data_size);

            pb_free(biometric_header);
            pb_free(reference_data);
            
            if (ret != PB_EOK)
            {
                pb_free(reader_list);
                pb_release();
                return PB_EFATAL;
            }
        }
        else 
        {
            pb_free(biometric_header);
            pb_free(reference_data);
            
            printf("Reference data could not be validated!\n");
        }
    }
    else 
    {
        pb_free(reader_list);
    }
     
    printf("Enter 0 to return to main menu: ");
    scanf_s("%d", &selection);

    pb_release();
    return PB_EOK;
}

/****************************************************************************
*
* Description:
*  Stores the biometric header and reference data to a card with BioManager.
*
* Arguments:
*  biometric_header        - [in] Pointer to the biometric header.
*  biometric_header_size   - [in] Size of the biometric header.
*  reference_data          - [in] Pointer to the reference data.
*  reference_data_size     - [in] Size of the reference data.
*
* Return value:
*  Returns PB_EOK if successful, otherwise an error code is returned.
*
***************************************************************************/
static int store_template(unsigned char *biometric_header,
                          int            biometric_header_size,
                          unsigned char *reference_data,
                          int            reference_data_size)
{
    SCARDHANDLE     card_handle;
    LONG            result;
    BYTE            send_buffer[0xFF] = {0};
    BYTE            rec_buffer[0xFF] = {0};
    DWORD           rec_len;
    BYTE*           bio_header;
    BYTE*           ref_data;
    BYTE aid[] = { 0xA0, 0x00, 0x00, 0x00, 0x84, 0x00, 0x00 };
    
    int times = reference_data_size / APDU_DATA_SIZE;
    int rest =  reference_data_size % APDU_DATA_SIZE;
    int i;

    bio_header = malloc(biometric_header_size);
    ref_data = malloc(reference_data_size);

    /* This is the section that prepares the templates and stores them
       on the smart card. */

    /* Transfer the data to a more amenable form */
    memcpy(bio_header, biometric_header, biometric_header_size);
    memcpy(ref_data, reference_data, reference_data_size);

    /* Connect to the smart card */
    card_handle = connect_to_card();

    if (card_handle == SCARD_E_INVALID_HANDLE)
    {
        free(bio_header);
        free(ref_data);
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    /* Select the BioManager applet on the card. */
    send_buffer[0] = 0x00;
    send_buffer[1] = 0xA4;
    send_buffer[2] = 0x04;
    send_buffer[3] = 0x00;
    send_buffer[4] = sizeof(aid);
    memcpy(&send_buffer[5], aid, sizeof(aid));
    rec_len = sizeof(rec_buffer);

    result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
        sizeof(aid) + 5, NULL, rec_buffer, &rec_len);

    if (result != SCARD_S_SUCCESS)
    {
        free(bio_header);
        free(ref_data);
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    /* Store the templates. */

    /* Use begin transaction to smart card since it is opened in shared mode. */
    SCardBeginTransaction(card_handle);

    /* Store Biometric Header */
    send_buffer[0] = 0xB0;
    send_buffer[1] = 0x30;
    send_buffer[2] = 0x00;
    send_buffer[3] = 0x00;
    send_buffer[4] = biometric_header_size;
    memcpy(&send_buffer[5], bio_header, biometric_header_size);
    rec_len = sizeof(rec_buffer);

    result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
        biometric_header_size + 5, NULL, rec_buffer, 
        &rec_len);

    if (result != SCARD_S_SUCCESS || 
        !(rec_buffer[0] == 0x90 && rec_buffer[1] == 0))
    {
        free(bio_header);
        free(ref_data);
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    for (i = 0; i < times; i++)
    {
        send_buffer[0] = 0xb0;
        send_buffer[1] = 0x30;
        send_buffer[2] = 0x00;
        send_buffer[3] = 0x01;
        send_buffer[4] = APDU_DATA_SIZE;

        memcpy((unsigned char*)send_buffer + 5, 
               (unsigned char*)reference_data + (i * APDU_DATA_SIZE), 
               APDU_DATA_SIZE);

        rec_len = sizeof(rec_buffer);

        result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
            APDU_DATA_SIZE + 5, NULL, rec_buffer, &rec_len);

        if (result != SCARD_S_SUCCESS || 
            !(rec_buffer[0] == 0x90 && rec_buffer[1] == 0))
        {
            free(bio_header);
            free(ref_data);
            fprintf(stderr, "Smart card error.\n");
            return PB_EFATAL;
        }
    }

    if (rest > 0)
    {
        send_buffer[0] = 0xb0;
        send_buffer[1] = 0x30;
        send_buffer[2] = 0x00;
        send_buffer[3] = 0x01;
        send_buffer[4] = rest;

        memcpy((unsigned char*)send_buffer+5, 
               (unsigned char*)reference_data+(i * APDU_DATA_SIZE), 
               rest);

        rec_len = sizeof(rec_buffer);

        result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
            rest + 5, NULL, rec_buffer, &rec_len);

        if (result != SCARD_S_SUCCESS || 
            !(rec_buffer[0] == 0x90 && rec_buffer[1] == 0))
        {
            free(bio_header);
            free(ref_data);
            fprintf(stderr, "Smart card error.\n");
            return PB_EFATAL;
        }
    }

    free(bio_header);
    free(ref_data);

    /* Finalize */
    send_buffer[0] = 0xB0;
    send_buffer[1] = 0x30;
    send_buffer[2] = 0x00;
    send_buffer[3] = 0x02;
    send_buffer[4] = 0x00;
    rec_len = sizeof(rec_buffer);

    result = SCardTransmit(card_handle, SCARD_PCI_T0, send_buffer, 
        5, NULL, rec_buffer, &rec_len);

    /* Commit transaction to smart card. */
    SCardEndTransaction(card_handle, SCARD_LEAVE_CARD);

    if (result != SCARD_S_SUCCESS || 
        !(rec_buffer[0] == 0x90 && rec_buffer[1] == 0))
    {
        fprintf(stderr, "Smart card error.\n");
        return PB_EFATAL;
    }

    /* Disconnect from the smart card */
    SCardDisconnect(card_handle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);

    printf("Templates successfully written to the smart card!\n\n");

    return PB_EOK;
}

/****************************************************************************
*
* Description:
*  Get a handle to a smart card. Only T=0 cards are supported.
*
* Arguments:
*
* Return value:
*  Returns a handle to a smart card.
*
***************************************************************************/
static SCARDHANDLE connect_to_card(void)
{
    LONG res;
    SCARD_READERSTATE reader_state;
    SCARDHANDLE card;
    LPTSTR reader, reader_list;
    DWORD reader_list_size;
    DWORD protocol;

    res = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context);
    if (res != SCARD_S_SUCCESS)
    {
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    res = SCardListReaders(context, NULL, NULL, &reader_list_size);
    if (res != SCARD_S_SUCCESS)
    {
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    reader_list = malloc(reader_list_size);
    if (reader_list == NULL)
    {
        SCardReleaseContext(context);
        fprintf(stderr, "Not enough memory.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    res = SCardListReaders(context, NULL, reader_list, &reader_list_size);
    if (res != SCARD_S_SUCCESS)
    {
        free(reader_list);
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    reader = reader_list;

    reader_state.szReader = malloc(strlen(reader) + 1);
    if (reader_state.szReader == NULL)
    {
        free(reader_list);
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    strcpy_s((char*)reader_state.szReader, strlen(reader) + 1, reader);
    reader_state.dwCurrentState	= SCARD_STATE_UNAWARE;

    free(reader_list);

    res = SCardGetStatusChange(context, 0, &reader_state, 1);
    if (res != SCARD_S_SUCCESS)
    {
        free((void*)reader_state.szReader);
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    if (!(reader_state.dwEventState & SCARD_STATE_PRESENT))
    {
        free((void*)reader_state.szReader);
        SCardReleaseContext(context);
        fprintf(stderr, "Please insert a card.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    res = SCardConnect(context, reader_state.szReader, SCARD_SHARE_SHARED,
        SCARD_PROTOCOL_T0, &card, &protocol);
    free((void*)reader_state.szReader);
    if (res != SCARD_S_SUCCESS)
    {
        SCardReleaseContext(context);
        fprintf(stderr, "No contact with reader.\n");
        return SCARD_E_INVALID_HANDLE;
    }

    return card;
}

/****************************************************************************
*
* Callback function implementations
*
****************************************************************************/
/****************************************************************************
*
* Description:
*  Callback function for capture_image_callback()
*
* Arguments:
*  token        - [in] callback identifier.
*  context      - [in/out] Pointer to user defined data.
*
* Return value:
*  Returns PB_EOK if successful, otherwise an error code is returned.
*
****************************************************************************/
static void capture_image_callback(int   token,
                                   void *context)
{
    pb_image_t *image;
    int		    ret, present, condition, quality;
    
    /* Retreive the finger status */
    ret = pb_cb_finger_status(token, &image, &quality, &condition, &present);

    if (ret != PB_EOK)
    {
        print_error_reason(ret);
        fprintf(stderr, "::FINGER_PRESENT\n");
        pb_cb_cancel(token);
        return;
    }

    if (!present)
    {
        printf("callback_enrol : Please place finger on sensor.\n");
        return;
    }

    if ((condition != PB_STATUS_OK) &&
        (condition != PB_STATUS_UNKNOWN))
    {
        printf("Finger condition is: ");
        if (condition == PB_STATUS_TOO_WET)
            printf("too wet [%d].\n", quality);
        if (condition == PB_STATUS_TOO_DRY)
            printf("too dry [%d].\n", quality);
        return;
    }
}

/****************************************************************************
*
* Description:
*  Callback function for pb_wait_for_no_finger()
*
* Arguments:
*  token        - [in] callback identifier.
*  context      - [in/out] Pointer to user defined data.
*
* Return value:
*  Returns PB_EOK if successful, otherwise an error code is returned.
*
****************************************************************************/
static void no_finger_callback(int   token,
                               void *context)
{
    pb_image_t *image;
    int		    ret, present;
    
    ret = pb_cb_finger_status(token, &image, NULL, NULL, &present);

    if (ret != PB_EOK)
    {
        print_error_reason(ret);
        fprintf(stderr, "::FINGER_PRESENT\n");
        pb_cb_cancel(token);
        return;
    }

    if (present)
    {
        printf("Please lift your finger.\n");
        return;
    }
}

/****************************************************************************
*
* Description:
*  Print information regarding the error code returned by the framework.
*
* Arguments:
*  ret     - [in] Error code returned by the framework.
*
* Return value:
*  None
*
***************************************************************************/
static void print_error_reason(int ret)
{
    switch(ret)
    {
    case PB_EBUFFER:
        fprintf(stderr, "ERROR::INCORRECT BUFFER SIZE\n");
        return;

    case PB_ECANCEL:
        fprintf(stderr, "ERROR::CANCELED BY CALLER");
        return;

    case PB_EFATAL:
        fprintf(stderr, "ERROR::UNSPECIFIED FATAL ERROR\n");
        return;

    case PB_EBIR:
        fprintf(stderr, "ERROR::UNRECOGNIZED/CORRUPT BIR\n");
        return;

    case PB_EDATA:
        fprintf(stderr, "ERROR::WRONG FORMAT OF DATA\n");
        return;

    case PB_EREADER:
        fprintf(stderr, "ERROR::WRONG READER HANDLE\n");
        return;

    case PB_EMEMORY:
        fprintf(stderr, "ERROR::CANNOT ALLOCATE MEMORY\n");
        return;

    case PB_EINIT:
        fprintf(stderr, "ERROR::INTERFACE NOT INITIALIZED\n");
        return;

    case PB_ESUPPORT:
        fprintf(stderr, "ERROR::OPERATION NOT SUPPORTED\n");
        return;

    case PB_EPARAMETER:
        fprintf(stderr, "ERROR::INVALID PARAMETERS\n");
        return;

    case PB_ETIMEOUT:
        fprintf(stderr, "ERROR::TIMEOUT\n");
        return;

    default:
        fprintf(stderr, "ERROR::UNKNOWN ERROR CODE: %d\n", ret);
        return;
    }
}
