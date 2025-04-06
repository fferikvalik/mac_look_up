#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAC_STR_LEN 17    // Формат "XX:XX:XX:XX:XX:XX"

// Ключ и IV для AES-256-CBC (ОБЯЗАТЕЛЬНО измените на свои безопасные значения!)
const unsigned char enc_key[32] = "#E=~=Alc27!3w*YoGo6>:t*@8Zs?U£Vo";  // 256-битный ключ
const unsigned char enc_iv[16]  = "{t1Tj>1I4p:agGB0";                  // 128-битный IV

// Структура для хранения данных, полученных от libcurl
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback-функция для libcurl: записывает данные в динамическую память
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        fprintf(stderr, "Ошибка: недостаточно памяти (realloc вернул NULL).\n");
        return 0;
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0';
    return realsize;
}

// Приведение строки к верхнему регистру
void toUpperStr(char *str) {
    for (; *str; ++str)
        *str = toupper((unsigned char)*str);
}

// Проверка формата MAC-адреса: ожидается "XX:XX:XX:XX:XX:XX"
int validate_mac(const char *mac) {
    if (strlen(mac) != MAC_STR_LEN)
        return 0;
    for (int i = 0; i < MAC_STR_LEN; i++) {
        if (i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            if (mac[i] != ':')
                return 0;
        } else {
            if (!((mac[i] >= '0' && mac[i] <= '9') ||
                  (mac[i] >= 'A' && mac[i] <= 'F') ||
                  (mac[i] >= 'a' && mac[i] <= 'f')))
                return 0;
        }
    }
    return 1;
}

// Функция шифрования AES-256-CBC
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    if (!ctx) return -1;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, enc_iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Функция расшифрования AES-256-CBC
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    if (!ctx) return -1;
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, enc_iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) < 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;  // Ошибка расшифрования
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Функция чтения зашифрованного API-ключа из файла и его расшифрования
char *get_api_key(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Не удалось открыть файл %s\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    rewind(fp);
    
    unsigned char *encrypted_data = malloc(filesize);
    if (!encrypted_data) {
        fprintf(stderr, "Ошибка выделения памяти\n");
        fclose(fp);
        return NULL;
    }
    
    size_t read_bytes = fread(encrypted_data, 1, filesize, fp);
    fclose(fp);
    if (read_bytes != filesize) {
        fprintf(stderr, "Ошибка чтения файла\n");
        free(encrypted_data);
        return NULL;
    }
    
    // Предполагаем, что расшифрованный API-ключ будет не длиннее зашифрованных данных
    unsigned char *decrypted = malloc(filesize + 1);
    if (!decrypted) {
        fprintf(stderr, "Ошибка выделения памяти для расшифрованных данных\n");
        free(encrypted_data);
        return NULL;
    }
    
    int decrypted_len = decrypt(encrypted_data, filesize, decrypted);
    free(encrypted_data);
    if (decrypted_len < 0) {
        fprintf(stderr, "Ошибка расшифрования API-ключа\n");
        free(decrypted);
        return NULL;
    }
    decrypted[decrypted_len] = '\0';
    return (char *)decrypted;
}

// Функция для выполнения запроса к API с использованием API-ключа
void lookup_mac(const char *mac, const char *api_key) {
    char url[256];
    // Формируем URL запроса к API, передавая открытый MAC-адрес
    snprintf(url, sizeof(url), "https://api.macvendors.com/%s", mac);
    
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    if (curl_handle) {
        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        
        // Добавляем заголовок с API-ключом
        struct curl_slist *headers = NULL;
        char header_auth[256];
        snprintf(header_auth, sizeof(header_auth), "Authorization: Bearer %s", api_key);
        headers = curl_slist_append(headers, header_auth);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
        
        res = curl_easy_perform(curl_handle);
        if (res != CURLE_OK) {
            fprintf(stderr, "Ошибка запроса: %s\n", curl_easy_strerror(res));
        } else {
            printf("MAC-адрес: %s\n", mac);
            printf("Информация о производителе: %s\n", chunk.memory);
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl_handle);
    }
    
    free(chunk.memory);
    curl_global_cleanup();
}

// Функция для тестирования: последовательно обрабатывает список MAC-адресов
void run_tests(const char *api_key) {
    const char *test_macs[] = {
        "38:F9:D3:97:90:12",  // Пример: может вернуть "Not Found", если информации нет
        "00:1A:2B:3C:4D:5E"   // Пример: если база содержит запись
    };
    int num_tests = sizeof(test_macs) / sizeof(test_macs[0]);
    
    printf("\nЗапуск тестов...\n");
    for (int i = 0; i < num_tests; i++) {
        printf("\nТест %d: MAC-адрес: %s\n", i+1, test_macs[i]);
        if (!validate_mac(test_macs[i])) {
            printf("Неверный формат MAC-адреса. Тест провален.\n");
        } else {
            lookup_mac(test_macs[i], api_key);
        }
    }
}

int main(int argc, char *argv[]) {
    // Читаем API-ключ из зашифрованного файла "apikey.enc"
    char *api_key = get_api_key("apikey.enc");
    if (!api_key) {
        fprintf(stderr, "Не удалось получить API-ключ.\n");
        return EXIT_FAILURE;
    }
    
    // Если передан аргумент "test", запускаем тестовый режим
    if (argc > 1 && strcmp(argv[1], "test") == 0) {
        run_tests(api_key);
        free(api_key);
        return EXIT_SUCCESS;
    }
    
    char mac[32];  // Буфер для ввода
    printf("Введите MAC-адрес (формат XX:XX:XX:XX:XX:XX): ");
    if (scanf("%31s", mac) != 1) {
        fprintf(stderr, "Ошибка ввода\n");
        free(api_key);
        return EXIT_FAILURE;
    }
    
    toUpperStr(mac);
    if (!validate_mac(mac)) {
        fprintf(stderr, "Ошибка: неверный формат MAC-адреса.\n");
        free(api_key);
        return EXIT_FAILURE;
    }
    
    lookup_mac(mac, api_key);
    
    free(api_key);
    return EXIT_SUCCESS;
}
