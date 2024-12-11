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

    if(operation == DATA || operation == SIZE){
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
                // Todos enviam o nome do arquivo
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
                break; // Timeout ou erro: retransmitir
            }

            uint8_t responseSeq = getSeq(response.Header);
            uint8_t responseType = getType(response.Header);

            if (responseSeq == seq) {
                if (responseType == ACK || responseType == OK) {
                    seq = (seq + 1) % 32;
                    bytesRead = 0; // Preparar para o próximo pacote
                    break;
                } else if (responseType == NACK) {
                    printf("NACK recebido. Retransmitindo pacote %u...\n", seq);
                    break; // Retransmitir o mesmo pacote
                } else if (responseType == ERROR) {
                    fprintf(stderr, "Erro recebido do servidor. Operação abortada.\n");
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
    ssize_t bytesReceived;
    uint8_t expectedSeq = 0;
    char filename[FILENAME_SIZE] = {0};
    int receiving = 1;

    // Loop principal para receber pacotes
    while (receiving) {
        // Receber mensagem do socket
        bytesReceived = recv(sockfd, &msg, sizeof(msg), 0);

        // Verifica se houve erro ou fim da conexão
        if (bytesReceived < 0) {
            perror("Erro ao receber dados");
            break;
        } else if (bytesReceived == 0) {
            printf("Conexão encerrada pelo remetente.\n");
            break;
        }

        // Verificar marcador inicial e validade do pacote
        if (msg.MI == INIT_MARKER && isValidPackage(msg, bytesReceived, expectedSeq)) {
            *operation = getType(msg.Header);

            // Processar diferentes tipos de operações
            switch (*operation) {
                case DATA:
                    // Escrever dados recebidos no arquivo
                    if (file) {
                        size_t written = fwrite(msg.Data, 1, getTam(msg.Header), file);
                        if (written != getTam(msg.Header)) {
                            perror("Erro ao escrever no arquivo");
                            receiving = 0;
                        }
                    }
                    setType(&response.Header, ACK);
                    break;

                case BACKUP:
                case RESTORE:
                case VERIFY:
                    // Receber o nome do arquivo
                    receiveFilename(filename, &msg);
                    setType(&response.Header, OK);
                    break;

                case SIZE:
                    // Processar tamanho do arquivo
                    receiveSize(&msg, &response);
                    break;

                case OKCHECKSUM:
                    // Verificar integridade
                    receiveChecksum(&msg, &response, &outputFile);
                    break;

                case END:
                    // Finalizar operação
                    setType(&response.Header, ACK);
                    receiving = 0; // Sair do loop após receber END
                    break;

                default:
                    // Tipo de operação inválido
                    fprintf(stderr, "Operação inválida recebida.\n");
                    setType(&response.Header, ERROR);
                    receiving = 0;
                    break;
            }

            // Enviar resposta com sequência esperada
            setSeq(&response.Header, expectedSeq);
            expectedSeq = (expectedSeq + 1) % 32;

            if (send(sockfd, &response, sizeof(response), 0) < 0) {
                perror("Erro ao enviar resposta");
                break;
            }

            // Verificar se é o último pacote (tamanho menor que o máximo permitido)
            if (getTam(msg.Header) < MAX_DATA_SIZE && *operation == DATA) {
                receiving = 0;
            }

        } else {
            // Pacote inválido ou fora de sequência
            setSeq(&response.Header, expectedSeq);
            setType(&response.Header, NACK);

            if (send(sockfd, &response, sizeof(response), 0) < 0) {
                perror("Erro ao enviar NACK");
                break;
            }
        }
    }

    // Salvar o nome do arquivo recebido, se aplicável
    if (strlen(filename) > 0) {
        strncpy(outputFile, filename, FILENAME_SIZE - 1);
        outputFile[FILENAME_SIZE - 1] = '\0'; // Garantir terminação nula
    }

    // Verificar se o arquivo precisa ser fechado
    if (file) {
        fclose(file);
    }
}
