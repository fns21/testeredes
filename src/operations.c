#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <openssl/md5.h>

#include "message.h"
#include "utils.h"
#include "operations.h"

void partFileAndSend(const char *fileName, int sockfd, int operation) {
    Message msg, response;
    unsigned char tempBuffer[MAX_DATA_SIZE];

    uint8_t bytesRead = 0;
    int fileNameSize = strlen(fileName);
    int offset = 0;
    uint8_t seq = 0;
    FILE *file = NULL;
    int eof = 0;
    int maxRetransmissions = 5; // Limite de retransmissões
    int retransmissions = 0;

    if (operation == DATA || operation == SIZE) {
        file = fopen(fileName, "rb");
        if (!file) {
            operation = ERROR_CANT_FIND_FILE;
        }
    }
    
    int transferSuccess = 1; 
    while (!eof) {
        if (bytesRead == 0 && !eof) { // Ler novos dados apenas se não for retransmissão
            switch (operation) {
                case DATA:
                    sendData(file, &msg, &seq, &bytesRead, tempBuffer);
                    if (bytesRead < MAX_DATA_SIZE) eof = 1; // Fim do arquivo
                    break;
                case BACKUP:
                case RESTORE:
                case VERIFY:
                    setType(&msg.Header, operation);
                    sendFilename(fileName, &offset, fileNameSize, &msg, &seq, &bytesRead, tempBuffer);
                    if (offset >= fileNameSize) eof = 1; // Nome do arquivo concluído
                    break;
                case SIZE:
                    sendSize(fileName, &msg, &seq, &bytesRead);
                    eof = 1; // Operação SIZE sempre envia apenas uma vez
                    break;
                case OKCHECKSUM:
                    sendChecksum(fileName, &msg, &seq, &bytesRead);
                    eof = 1; // Operação OKCHECKSUM sempre envia apenas uma vez
                    break;
                case END:
                    fillPackage(&msg, seq, bytesRead, END, NULL);
                    eof = 1;
                    break;

                default:
                    fprintf(stderr, "Operação desconhecida.\n");
                    transferSuccess = 0;
                    break;
            }
        }

        // Enviar pacote
        if (send(sockfd, &msg, sizeof(msg), 0) < 0) {
            perror("Erro ao enviar pacote");
            break;
        }

        // Configurar timeout e aguardar resposta
        long long start = timestamp();
        configureTimeout(sockfd);

        while (1) {
            recv(sockfd, &response, sizeof(response), 0);
            if (timestamp() - start > TIMEOUT_MILLIS) {
                printf("Timeout para o pacote %u. Reenviando...\n", seq);
                if (++retransmissions > maxRetransmissions) {
                    fprintf(stderr, "Falha: número máximo de retransmissões atingido.\n");
                    transferSuccess = 0;
                    eof = 1; // Finaliza a transferência
                }
                break; // Timeout ou erro: retransmitir
            }

            uint8_t responseSeq = getSeq(response.Header);
            uint8_t responseType = getType(response.Header);

            if (responseSeq == seq) {
                if (responseType == ACK || responseType == OK) {
                    seq = (seq + 1) % 32;
                    bytesRead = 0; // Preparar para o próximo pacote
                    retransmissions = 0; // Reseta contador de retransmissões
                    break;
                } else if (responseType == NACK) {
                    printf("NACK recebido. Retransmitindo pacote %u...\n", seq);
                    if (++retransmissions > maxRetransmissions) {
                        fprintf(stderr, "Falha: número máximo de retransmissões atingido.\n");
                        transferSuccess = 0;
                        eof = 1; // Finaliza a transferência
                    }
                    break; // Retransmitir o mesmo pacote
                } else if (responseType == ERROR) {
                    fprintf(stderr, "Erro recebido do servidor. Operação abortada.\n");
                    transferSuccess = 0;
                    eof = 1;
                    break;
                }
            } else if (responseSeq == (seq + 1) % 32) {
                printf("Pacote duplicado ignorado.\n");
                seq = (seq + 1) % 32;
                bytesRead = 0; // Avançar para o próximo pacote
                break;
            }
        }
    }

    if (file) fclose(file);

    if (transferSuccess) {
        printf("Transferência concluída com sucesso.\n");
    } else {
        fprintf(stderr, "Erro durante a transferência.\n");
    }
}

void recvPkgAndAssemble(char *outputFile, int sockfd, FILE *file, int *operation) {
    Message msg, response;
    uint8_t bytesReceived = 0;
    uint8_t expectedSeq = 0;
    char filename[FILENAME_SIZE] = {0};

    while (1) {
        // Inicializa o buffer do pacote
        memset(&msg, 0, sizeof(msg));
        
        // Recebe o pacote
        bytesReceived = recv(sockfd, &msg, sizeof(msg), 0);
        
        if (bytesReceived <= 0) {
            if (bytesReceived == 0) {
                printf("Conexão encerrada pelo cliente.\n");
            } else {
                perror("Erro ao receber dados");
            }
            break;
        }

        // Verifica se o pacote recebido é válido
        if (bytesReceived < sizeof(msg)) {
            printf("Pacote incompleto recebido (%d bytes). Ignorando.\n", bytesReceived);
            continue; // Ignora pacotes incompletos
        }

        // Valida o pacote recebido
        if (msg.MI == INIT_MARKER){
            if(isValidPackage(msg, bytesReceived, expectedSeq)) {
                *operation = getType(msg.Header);
                
                switch (*operation) {
                    case DATA:
                        receiveData(&msg, file, &response);
                        break;
                    case BACKUP:
                    case RESTORE:
                    case VERIFY:
                        receiveFilename(filename, &msg);
                        setType(&response.Header, OK);
                        break;
                    case SIZE:
                        receiveSize(&msg, &response);
                        break;
                    case OKCHECKSUM: 
                        receiveChecksum(&msg, &response, &outputFile);
                        break;
                    case END:
                        setType(&response.Header, ACK);
                        break;
                    default:
                        setType(&response.Header, ERROR);
                        break;
                }

                // Envia resposta ACK para o pacote válido
                setSeq(&response.Header, expectedSeq);
                expectedSeq = (expectedSeq + 1) % 32;
                send(sockfd, &response, sizeof(response), 0);

                // Se o tamanho dos dados for menor que o máximo, assumimos fim da transmissão
                if (getTam(msg.Header) < MAX_DATA_SIZE) {
                    break;
                }
            }
            else {
                // Pacote inválido ou fora de sequência: enviar NACK somente se fora de sequência
                uint8_t receivedSeq = getSeq(msg.Header);
                if (receivedSeq != expectedSeq) {
                    printf("Pacote fora de sequência (esperado: %d, recebido: %d). Enviando NACK.\n", expectedSeq, receivedSeq);
                    setSeq(&response.Header, expectedSeq);
                    setType(&response.Header, NACK);
                    send(sockfd, &response, sizeof(response), 0);
                } else {
                    printf("Pacote inválido. Ignorando.\n");
                }
            }
        }
    }

    // Processa o nome do arquivo, se necessário
    if (strlen(filename) > 0) {
        strcpy(outputFile, getFileName(filename));
    }
}
