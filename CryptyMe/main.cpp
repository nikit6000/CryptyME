//
//  main.cpp
//  CryptyMe
//
//  Created by Никита on 01.08.2018.
//  Copyright © 2018 nproject. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <math.h>
#include <string.h>
#include <openssl/err.h>

#include "qr.h"

#define IMAGE_RATIO_W       16
#define IMAGE_RATIO_H       9
#define RSA_KEY_BITS        2048
#define RSA_BLOCK_SIZE      (RSA_KEY_BITS/16)
#define RSA_ENC_BLOCK_SIZE  (RSA_BLOCK_SIZE*2)
#define INFO_HEADER_SIZE    24

using namespace std;


int decrypt_image(char * file, char * key);
int generate_image(char * file);
RSA * generate_key();
static char * read_file_bytes(const char * filename, long * read);
uint8_t * encrypt_data(uint8_t * data, long len, int * bc);
uint8_t * decrypt_data(uint8_t * data, long len, char * key_path, int * total);

void int_to_array(uint32_t v, uint8_t * ptr, int offset);
void long_to_array(uint64_t v, uint8_t * ptr, int offset);
uint32_t read_int(uint8_t * ptr, int offset);
uint64_t read_long(uint8_t * ptr, int offset);


int main(int argc, const char * argv[]) {
    
    char defaultKey[] = "private.pem";
    
    char * to_decrypt = NULL;
    char * to_encrypt = NULL;
    char * key = defaultKey;
    
    if (argc > 1) {
        for(int i = 0; i < argc; i++) {
            if (strcmp("-e", argv[i]) == 0 && i + 1 < argc) {
                to_encrypt = (char*)argv[i + 1];
            } else if (strcmp("-d", argv[i]) == 0 && i + 1 < argc) {
                to_decrypt = (char*)argv[i + 1];
            } else if (strcmp("-k", argv[i]) == 0 && i + 1 < argc) {
                key = (char*)argv[i + 1];
            }
        }
    } else {
        cout << "Usage: CrypryMe [args]\nArgs:\n\t-e <file_name> - encrypt file.\n\t-d <file_name> - decrypt file.\n\t-k <private_key_pem> - set private key.\n";
    }
    
    if (to_encrypt != NULL) {
        generate_image(to_encrypt);
    }
    
    if (to_decrypt != NULL) {
        decrypt_image(to_decrypt, key);
    }
    
    return 0;
}

int decrypt_image(char * file, char * key) {
    long readed = 0;
    int offset, ret = 0;
    int new_line_count = 0;
    FILE * e_file;
    uint8_t * encrypted_data = (uint8_t *)read_file_bytes(file, &readed);
    
    if (encrypted_data == NULL) {
        cout << "Error: Can't read input file \"" << file << "\"\n";
        return -1;
    }
    
    for (offset = 0; offset < readed; offset++)
        if (encrypted_data[offset] == '\n')
            if (++new_line_count == 4) {
                offset++;
                break;
            }

    
    char * ppm_header = (char *)malloc(offset);
    
    memcpy(ppm_header, encrypted_data, offset);
    
    ppm_header[offset - 1] = '\0';
    
    int img_w, img_h;
    
    sscanf(ppm_header, "%*s\n%d\n%d\n%*d", &img_w, &img_h);
    
    int qr_w = read_int(encrypted_data, offset);
    int qr_h = read_int(encrypted_data, offset + 4);
    int qr_x = read_int(encrypted_data, offset + 8);
    int qr_y = read_int(encrypted_data, offset + 12);
    long payload_size = read_long(encrypted_data, offset + 16);
    
    cout << "HEADER: " << offset + INFO_HEADER_SIZE << " bytes\n";
    
    cout << "ENCRYPTED IMAGE LOADED. W: " << img_w << " H: " << img_h << "\n";
    cout << "QR W: " << qr_w << " H: " <<  qr_h << " X: " << qr_x << " Y: " << qr_y << "\n";
    cout << "PAYLOAD SIZE: " << payload_size << "\n\n";
    
    uint8_t * payload = (uint8_t *)malloc(payload_size);
    
    int payload_index = 0;
    
    for (int i = offset + INFO_HEADER_SIZE; i < readed; i++) {
        int y = (i - offset) / (img_w * 3);
        int x = (i - offset) - y * img_w * 3;
        
        if (y >= qr_y && y < qr_y + QR_HEIGHT)
            if (x >= (qr_x * 3) && x < (qr_x + QR_WIDTH) * 3)
                continue;
        
        if (payload_index >= payload_size )
            break;
        
        payload[payload_index++] = encrypted_data[i];
    }
    
    cout << "Decrypring...\n";
    
    int decrypted_size = 0;
    uint8_t * decrypted_data = decrypt_data(payload, payload_size, key, &decrypted_size);
    
    if (decrypted_data == NULL) {
        cout << "Error: Can't write file 'decrypted_meme.jpg'\n";
        ret = -1;
        goto freeAll;
    }
    
    e_file = fopen("decrypted_meme.jpg", "wb");
    
    if (e_file == NULL) {
        cout << "Error: Can't write file 'decrypted_meme.jpg'\n";
        ret = -1;
        goto freeAll;
    }
    
    fwrite(decrypted_data, 1, decrypted_size, e_file);
    fclose(e_file);
freeAll:
    free(decrypted_data);
    free(payload);
    free(encrypted_data);
    free(ppm_header);
    return ret;
}

int generate_image(char * file) {
    int ret = 0;
    long readed = 0;
    uint8_t * meme_data = (uint8_t *)read_file_bytes(file, &readed);
    
    cout << "Encrypring...\n";
    
    int block_count = 0;
    uint8_t * data = encrypt_data(meme_data, readed, &block_count);
    
    if (data != NULL) {
        long total_size = INFO_HEADER_SIZE + qr_code_size + block_count * RSA_ENC_BLOCK_SIZE;
        int mul = ceil(sqrt((double)total_size / (double)(16 * 9 * 3)));
        int width = IMAGE_RATIO_W * mul;
        int height = IMAGE_RATIO_H * mul;
        
        if (height < QR_HEIGHT) {
            height = QR_HEIGHT;
            width = height * IMAGE_RATIO_W / IMAGE_RATIO_H;
        }
        
        uint8_t image[height][width * 3];
        
        memset(image, 0, width * height * 3);
        
        
        
        int qr_x = (width - QR_WIDTH) / 2;
        int qr_y = (height - QR_HEIGHT) / 2;
        
        cout << "IMAGE W: " << width << " H: " << height << "\nQR X: " << qr_x << " Y: " << qr_y << "\n";
        
        for (int row = 0; row < QR_HEIGHT; row++) {
            memcpy(&image[qr_y + row][qr_x * 3], qr_code + QR_WIDTH * row * 3, QR_WIDTH * 3);
        }
        
        int_to_array(QR_WIDTH, *image, 0);
        int_to_array(QR_HEIGHT, *image, 4);
        int_to_array(qr_x, *image, 8);
        int_to_array(qr_y, *image, 12);
        long_to_array(block_count * RSA_ENC_BLOCK_SIZE, *image, 16);
        
        long data_index = 0;
        
        
        for (int i = INFO_HEADER_SIZE; i < width * height * 3; i++) {
            int y = i / (width * 3);
            int x = i - y * width * 3;
            
            if (y >= qr_y && y < qr_y + QR_HEIGHT)
                if (x >= (qr_x * 3) && x < (qr_x + QR_WIDTH) * 3)
                    continue;
            
            if (data_index >= RSA_ENC_BLOCK_SIZE * block_count )
                break;
            
            image[y][x] = data[data_index++];
        }
        
        char * ppm_header = (char *)malloc(512);
        
        sprintf(ppm_header, "P6\n%d\n%d\n255\n", width, height);
        
        uint8_t * ppm_image = (uint8_t *)malloc(strlen(ppm_header) + width * height * 3);
        
        memcpy(ppm_image, ppm_header, strlen(ppm_header));
        
        memcpy(ppm_image + strlen(ppm_header), &image[0][0], width * height * 3);
        
        cout << "FULL HEADER SIZE: " << strlen(ppm_header) + INFO_HEADER_SIZE << "\n";
        
        FILE * o_file = fopen("meme.ppm", "wb");
        
        if (o_file == NULL) {
            ret = -1;
            goto freeImage;
        }
        
        fwrite(ppm_image, 1, strlen(ppm_header) + width * height * 3, o_file);
        fclose(o_file);
    freeImage:
        free(ppm_image);
        free(ppm_header);
        
    } else {
        ret = -1;
    }
    
freeAll:
    free(meme_data);
    free(data);
    std::cout << "done bc: " << block_count << "\n";
    
    return ret;
}

uint8_t * encrypt_data(uint8_t * data, long len, int * bc) {
    int blocks_count = ceil((double)len / (double)RSA_BLOCK_SIZE);
    uint8_t * blocks = (uint8_t *)malloc(RSA_ENC_BLOCK_SIZE * blocks_count);
    memset(blocks, 0, RSA_ENC_BLOCK_SIZE * blocks_count);
    //uint8_t * buffer = (uint8_t *)malloc(RSA_BLOCK_SIZE);
    
    RSA * keypair = generate_key();
    
    int encrypt_len;
    char * err = (char *)malloc(130);
    
    for (int b = 0; b < blocks_count; b++) {
        long bytes_to_encrypt = ((len - b * RSA_BLOCK_SIZE) > 0) ? RSA_BLOCK_SIZE : (len - b * RSA_BLOCK_SIZE);
        int padding = RSA_PKCS1_OAEP_PADDING;
        
        if((encrypt_len = RSA_public_encrypt((int)bytes_to_encrypt, data + b * RSA_BLOCK_SIZE, blocks + b * RSA_ENC_BLOCK_SIZE, keypair, padding)) == -1) {
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            fprintf(stderr, "Error encrypting message: %s\n", err);
            free(blocks);
            return NULL;
        }
    }
    
    cout << "ENCRYPTED " << len << " BYTES\n";
    
    *bc = blocks_count ;
    
    return blocks;
}

uint8_t * decrypt_data(uint8_t * data, long len, char * key_path, int * total){
    
    int blocks_count = (int)len / (RSA_ENC_BLOCK_SIZE);
    
    uint8_t * decrypted_data = (uint8_t *)malloc(len);
    
    FILE *fp = fopen(key_path, "r");
    
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);

    int total_size = 0;
    char * err = (char *)malloc(130);
    
    for (int b = 0; b < blocks_count; b++) {
        int rsa_outlen  = RSA_private_decrypt(RSA_ENC_BLOCK_SIZE, data + b * RSA_ENC_BLOCK_SIZE, decrypted_data + b * RSA_BLOCK_SIZE, rsa, RSA_PKCS1_OAEP_PADDING);
        
        
        if (rsa_outlen == -1) {
            ERR_load_crypto_strings();
            ERR_error_string(ERR_get_error(), err);
            fprintf(stderr, "Error encrypting message: %s\n", err);
            free(decrypted_data);
            return NULL;
        }
        
        total_size += rsa_outlen;
    }
    
    *total = total_size;
    
    cout << "DECRYPTED " << total_size << " BYTES\n";
    
    return decrypted_data;
}

RSA * generate_key()
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;
    
    int             bits = RSA_KEY_BITS;
    unsigned long   e = RSA_F4;
    
    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
    
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }
    
    // 2. save public key
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        goto free_all;
    }
    
    // 3. save private key
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    
    // 4. free
free_all:
    
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    //RSA_free(r);
    BN_free(bne);
    
    return r;
}

static char * read_file_bytes(const char * filename, long * read)
{
    ifstream ifs(filename, ios::binary | ios::ate);
    ifstream::pos_type pos = ifs.tellg();
    
    long length = pos;
    
    char *pChars = (char *)malloc(length);
    ifs.seekg(0, ios::beg);
    ifs.read(pChars, length);

    ifs.close();
    *read = length;
    return pChars;
}

void int_to_array(uint32_t v, uint8_t * ptr, int offset) {
    *(ptr + offset) = (uint8_t)(v & 0xFF);
    *(ptr + offset + 1) = (uint8_t) ((v >> 8) & 0xFF);
    *(ptr + offset + 2) = (uint8_t) ((v >> 16) & 0xFF);
    *(ptr + offset + 3) = (uint8_t) ((v >> 24) & 0xFF);
}

void long_to_array(uint64_t v, uint8_t * ptr, int offset) {
    *(ptr + offset) = (uint8_t)(v & 0xFF);
    *(ptr + offset + 1) = (uint8_t) ((v >> 8) & 0xFF);
    *(ptr + offset + 2) = (uint8_t) ((v >> 16) & 0xFF);
    *(ptr + offset + 3) = (uint8_t) ((v >> 24) & 0xFF);
    *(ptr + offset + 4) = (uint8_t) ((v >> 32) & 0xFF);
    *(ptr + offset + 5) = (uint8_t) ((v >> 40) & 0xFF);
    *(ptr + offset + 6) = (uint8_t) ((v >> 48) & 0xFF);
    *(ptr + offset + 7) = (uint8_t) ((v >> 56) & 0xFF);
}

uint32_t read_int(uint8_t * ptr, int offset) {
    
    uint32_t a, b, c, d;
    
    a = *(ptr + offset);
    b = *(ptr + offset + 1);
    c = *(ptr + offset + 2);
    d = *(ptr + offset + 3);
    
    return a | (b << 8) | (c << 16) | (d << 24);
}

uint64_t read_long(uint8_t * ptr, int offset) {
    
    uint64_t a, b, c, d, e, f, g, h;
    
    a = *(ptr + offset);
    b = *(ptr + offset + 1);
    c = *(ptr + offset + 2);
    d = *(ptr + offset + 3);
    e = *(ptr + offset + 4);
    f = *(ptr + offset + 5);
    g = *(ptr + offset + 6);
    h = *(ptr + offset + 7);

    
    return a | (b << 8) | (c << 16) | (d << 24) | (e << 32) | (f << 40) | (g << 48) | (h << 56);
}

uint8_t * generate_image(uint8_t * encrypted_data, int len) {
    
    
    return NULL;
}
