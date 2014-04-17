/*
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

/* Configuration Headers */
/* Controls build behavior of components */
#include <ph_NxpBuild.h>
/* Status code definitions */
#include <ph_Status.h>

/* Reader Library Headers */
/* Generic ISO14443-3A Component of
 * Reader Library Framework */
#include <phpalI14443p3a.h>
/* Generic ISO14443-4 Component of
 * Reader Library Framework */
#include <phpalI14443p4.h>
/* Generic ISO14443-4A Component of
 * Reader Library Framework */
#include <phpalI14443p4a.h>
/* Generic MIFARE(R) Ultralight Application
 * Component of Reader Library Framework */
#include <phalMful.h>
#include <phalMfc.h>
/* Generic KeyStore Component of
 * Reader Library Framework */
/* In that example we don't use any
 * key. But we need the key components
 * for some function calls and you maight
 * need it when using crypto with
 * Ultralight-C cards. */
#include <phKeyStore.h>

#include <phpalSli15693.h>
#include <phpalSli15693_Sw.h>
#include <phpalFelica.h>
#include <phpalI14443p3b.h>

#define sak_ul                0x00
#define sak_ulc               0x00
#define sak_mini              0x09
#define sak_mfc_1k            0x08
#define sak_mfc_4k            0x18
#define sak_mfp_2k_sl1        0x08
#define sak_mfp_4k_sl1        0x18
#define sak_mfp_2k_sl2        0x10
#define sak_mfp_4k_sl2        0x11
#define sak_mfp_2k_sl3        0x20
#define sak_mfp_4k_sl3        0x20
#define sak_desfire           0x20
#define sak_jcop              0x28
#define sak_layer4            0x20

#define atqa_ul               0x4400
#define atqa_ulc              0x4400
#define atqa_mfc              0x0200
#define atqa_mfp_s            0x0400
#define atqa_mfp_s_2K         0x4400
#define atqa_mfp_x            0x4200
#define atqa_desfire          0x4403
#define atqa_jcop             0x0400
#define atqa_mini             0x0400
#define atqa_nPA              0x0800

#define mifare_ultralight     0x01
#define mifare_ultralight_c   0x02
#define mifare_classic        0x03
#define mifare_classic_1k     0x04
#define mifare_classic_4k     0x05
#define mifare_plus           0x06
#define mifare_plus_2k_sl1    0x07
#define mifare_plus_4k_sl1    0x08
#define mifare_plus_2k_sl2    0x09
#define mifare_plus_4k_sl2    0x0A
#define mifare_plus_2k_sl3    0x0B
#define mifare_plus_4k_sl3    0x0C
#define mifare_desfire        0x0D
#define jcop                  0x0F
#define mifare_mini           0x10
#define nPA                   0x11

#define MAX_WRITTABLE_SIZE     (12 * 4)


// Forward declarations
uint32_t ReadMifare(void *halReader, phalMful_Sw_DataParams_t *alMful, phpalI14443p3a_Sw_DataParams_t *I14443p3a, char *mode, uint8_t *data);
uint32_t is_mifare_ultralight_card(uint8_t *bSak, uint8_t *pAtqa);
uint32_t is_mifare_card(uint8_t *bSak, uint8_t *pAtqa);
phStatus_t readerIC_Cmd_SoftReset(void *halReader);

void print_usage() {
    printf("Usage: explore-nfc-api <poll | write> [write message]\n");
}

int main(int argc, char **argv) {
    //check options
    if (argc < 2 || argc > 3) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "poll") != 0 && strcmp(argv[1], "write") != 0) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "write") == 0 && argc != 3) {
        print_usage();
        return 1;
    }

    phbalReg_R_Pi_spi_DataParams_t spi_bal;
    void *bal;

    phhalHw_Rc523_DataParams_t hal;
    void *pHal;
    phStatus_t status;

    uint8_t bHalBufferReader[0x40];

    // Initialize the Reader BAL (Bus Abstraction Layer) component
    status = phbalReg_R_Pi_spi_Init(&spi_bal, sizeof(phbalReg_R_Pi_spi_DataParams_t));
    if (PH_ERR_SUCCESS != status) {
        printf("Failed to initialize SPI\n");
        return 2;
    }
    bal = (void *)&spi_bal;

    status = phbalReg_OpenPort((void*)bal);
    if (PH_ERR_SUCCESS != status) {
        printf("Failed to open bal, try to run as sudo\n");
        return 3;
    }

    // we have a board with PN512, but on the software point of view, it's compatible to the RC523
    status = phhalHw_Rc523_Init(&hal,
                                sizeof(phhalHw_Rc523_DataParams_t),
                                bal,
                                0,
                                bHalBufferReader,
                                sizeof(bHalBufferReader),
                                bHalBufferReader,
                                sizeof(bHalBufferReader));
    pHal = &hal;

    if (PH_ERR_SUCCESS != status) {
        printf("Failed to initialize the HAL\n");
        return 4;
    }

    // Set the HAL configuration to SPI
    status = phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_BAL_CONNECTION, PHHAL_HW_BAL_CONNECTION_SPI);
    if (PH_ERR_SUCCESS != status) {
        printf("Failed to set hal connection SPI\n");
        return 5;
    }

    //Init all layers
    phpalI14443p4_Sw_DataParams_t I14443p4;
    phpalMifare_Sw_DataParams_t palMifare;
    phpalI14443p3a_Sw_DataParams_t I14443p3a;

    phalMful_Sw_DataParams_t alMful;

    //Initialize the 14443-3A PAL (Protocol Abstraction Layer) component
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p3a_Sw_Init(&I14443p3a, sizeof(phpalI14443p3a_Sw_DataParams_t), pHal));

    // Initialize the 14443-4 PAL component
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p4_Sw_Init(&I14443p4, sizeof(phpalI14443p4_Sw_DataParams_t), pHal));

    // Initialize the Mifare PAL component
    PH_CHECK_SUCCESS_FCT(status, phpalMifare_Sw_Init(&palMifare, sizeof(phpalMifare_Sw_DataParams_t), pHal, &I14443p4));

    // Initialize Ultralight(-C) AL component
    PH_CHECK_SUCCESS_FCT(status, phalMful_Sw_Init(&alMful, sizeof(phalMful_Sw_DataParams_t), &palMifare, NULL, NULL, NULL));


    /**************************************************************************
     * Begin the polling/writting
     *************************************************************************/
    printf("Starting %s \n", argv[1]);
    fflush(stdout);

    for(;;) {
        if (ReadMifare(pHal, &alMful, &I14443p3a, argv[1], (uint8_t *)argv[2])) {
            //reset the IC
            readerIC_Cmd_SoftReset(pHal);
        }
        //else no card in the field

        sleep(1); //poll every second
    }

    phhalHw_FieldOff(pHal);
    return 0;
}

//Only Mifare ultralight supported for now ...
uint32_t ReadMifare(void *hal, phalMful_Sw_DataParams_t *alMful, phpalI14443p3a_Sw_DataParams_t *I14443p3a, char *mode, uint8_t *data) {

    uint8_t bUid[10];
    uint8_t bLength;
    uint8_t bMoreCardsAvailable;
    uint32_t sak_atqa = 0;
    uint8_t pAtqa[2];
    uint8_t bSak[1];
    phStatus_t status;

    // Reset the RF field
    PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldReset(hal));

    // Apply the type A protocol settings and activate the RF field.
    PH_CHECK_SUCCESS_FCT(status, phhalHw_ApplyProtocolSettings(hal, PHHAL_HW_CARDTYPE_ISO14443A));

    // Empty the pAtqa
    memset(pAtqa, '\0', 2);
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p3a_RequestA(I14443p3a, pAtqa));

    // Reset the RF field
    PH_CHECK_SUCCESS_FCT(status, phhalHw_FieldReset(hal));

    // Empty the bSak
    memset(bSak, '\0', 1);

    // Activate one card after another
	bMoreCardsAvailable = 1;
	while (bMoreCardsAvailable) {
		// Activate the communication layer part 3 of the ISO 14443A standard.
		status = phpalI14443p3a_ActivateCard(I14443p3a, NULL, 0x00, bUid, &bLength, bSak, &bMoreCardsAvailable);

        if (status) {
            return false; //no card detected
        }
        printf("{\n");
		printf("\t\"mode\" : \"%s\",\n", mode);
        printf("\t\"uid\" : \"");
        uint8_t uidIndex;
        for(uidIndex = 0; uidIndex < bLength; uidIndex++) {
            printf("%02X", bUid[uidIndex]);
        }
        printf("\",\n");

        if (!is_mifare_ultralight_card(bSak, pAtqa)) {
            //not mifare ultralight,
            return false;
        }
        printf("\t\"data\" : \"");
        //Mifare ultralight
        if (strcmp(mode, "write") == 0) {
            //write data on card
            uint8_t full_buffer[MAX_WRITTABLE_SIZE];
            memset(full_buffer, '\0', MAX_WRITTABLE_SIZE);
            memcpy(full_buffer, data, strlen(data));

            int p;
            uint8_t bBufferWritter[4];
            for (p = 4; p <= 15; p++) {
                memset(bBufferWritter, '\0', 4);
                memcpy(bBufferWritter, full_buffer + (p - 4) * 4, 4);
                PH_CHECK_SUCCESS_FCT(status, phalMful_Write(alMful, p, bBufferWritter));
                int j;
                for(j = 0; j < 4; j++){
                    printf("%02X", bBufferWritter[j]);
                }
            }
        } else {
            //read data on card
            uint8_t bBufferReader[4];
            //data on the card are located at address (pages) 04 to 0F (15)
            int p;
            for(p = 4; p <= 15; p++) {
                memset(bBufferReader, '\0', 4);
                PH_CHECK_SUCCESS_FCT(status, phalMful_Read(alMful, p, bBufferReader));
                int j;
                for(j = 0; j < 4; j++){
                    printf("%02X", bBufferReader[j]);
                }
            }
        }

        printf("\"\n}\n");
        fflush(stdout);

        //close the reader
		status = phpalI14443p3a_HaltA(I14443p3a);
	}
	return true;
}

uint32_t is_mifare_card(uint8_t *bSak, uint8_t *pAtqa) {
    uint16_t detected_card = 0xFFFF;
    uint32_t sak_atqa = bSak[0] << 24 | pAtqa[0] << 8 | pAtqa[1];
    sak_atqa &= 0xFFFF0FFF;
    // Detect mini or classic
    switch (sak_atqa) {
      case sak_mfc_1k << 24 | atqa_mfc:
        detected_card &= mifare_classic;
      break;
      case sak_mfc_4k << 24 | atqa_mfc:
        detected_card &= mifare_classic;
      break;
      case sak_mfp_2k_sl1 << 24 | atqa_mfp_s:
        detected_card &= mifare_classic;
      break;
      case sak_mini << 24 | atqa_mini:
        detected_card &= mifare_mini;
      break;
      case sak_mfp_4k_sl1 << 24 | atqa_mfp_s:
        detected_card &= mifare_classic;
      break;
      case sak_mfp_2k_sl1 << 24 | atqa_mfp_x:
        detected_card &= mifare_classic;
      break;
      case sak_mfp_4k_sl1 << 24 | atqa_mfp_x:
        detected_card &= mifare_classic;
      break;
      default:
      break;
    }
    return detected_card == 0xFFFF;
}

uint32_t is_mifare_ultralight_card(uint8_t *bSak, uint8_t *pAtqa) {
    if (!is_mifare_card(bSak, pAtqa)) {
        return false;
    }
    uint8_t sak_atqa = bSak[0] << 24 | pAtqa[0] << 8 | pAtqa[1];
    return sak_ul << 24 | atqa_ul;
}

phStatus_t readerIC_Cmd_SoftReset(void *halReader) {
    phStatus_t status = PH_ERR_INVALID_DATA_PARAMS;
    switch (PH_GET_COMPID(halReader)) {
        case PHHAL_HW_RC523_ID:
            status = phhalHw_Rc523_Cmd_SoftReset(halReader);
        break;
    }
    return status;
}
