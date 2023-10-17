#include <stdio.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close

#define DCE_OPCODE_CLFLUSH            0
#define DCE_OPCODE_MEMCPY             1
#define DCE_OPCODE_MEMSET             2
#define DCE_OPCODE_MEMCMP             3
#define DCE_OPCODE_COMPRESS           4
#define DCE_OPCODE_DECOMPRESS         5
#define DCE_OPCODE_LOAD_KEY           6
#define DCE_OPCODE_CLEAR_KEY          7
#define DCE_OPCODE_ENCRYPT            8
#define DCE_OPCODE_DECRYPT            9
#define DCE_OPCODE_DECRYPT_DECOMPRESS 10
#define DCE_OPCODE_COMPRESS_ENCRYPT   11

typedef struct __attribute__((packed)) DCEDescriptor {
    uint8_t  opcode;
    uint8_t  ctrl;
    uint16_t operand0;
    uint32_t pasid;
    uint64_t source;
    uint64_t dest;
    uint64_t completion;
    uint64_t operand1;
    uint64_t operand2;
    uint64_t operand3;
    uint64_t operand4;
} __attribute__((packed)) DCEDescriptor;

#define DATA_SIZE         4000

#define RAW_READ          _IOR(0xAA, 0, struct AccessInfo*)
#define RAW_WRITE         _IOW(0xAA, 1, struct AccessInfo*)
#define SUBMIT_DESCRIPTOR _IOW(0xAA, 2, struct DescriptorInput*)

static void print_descriptor(DCEDescriptor * desc) {
    printf("\nSubmitting descriptor:\n   \
            opcode:     %u\n   \
            source:     0x%llx\n   \
            dest:       0x%llx\n   \
            completion: 0x%llx\n   \
            operand0:   %x\n   \
            operand1:   %llu\n   \
            operand2:   %llu\n",
            desc->opcode, desc->source,
            desc->dest, desc->completion, desc->operand0,
            desc->operand1, desc->operand2);

}

static void dce_memcpy(int fd, char * src, char * dest, uint64_t * completion) {
    DCEDescriptor desc = {
        DCE_OPCODE_MEMCPY,
        0,
        0,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        DATA_SIZE,0,0,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
}
static void memcpy_test(int fd, uint64_t * comp) {
    uint8_t * src = calloc(DATA_SIZE, sizeof(uint8_t));
    for (int i = 0; i < DATA_SIZE; i++) src[i] = (i % 16);
    uint8_t * dest = calloc(DATA_SIZE, sizeof(uint8_t));
    *comp = 0;
    printf("===============memcpy test===============\n");
    dce_memcpy(fd, src, dest, comp);
    if (memcmp(src, dest, DATA_SIZE)) {
        printf("ERROR: memcpy failed!\n");
    }
    else {
        printf("PASS: memcpy has passed");
    }
    printf("\n================test ended================\n\n");
    free(src);
    free(dest);
}
static void dce_memcmp(int fd, char * src, char * src2, char * dest, uint64_t * completion, bool bitmask) {
    DCEDescriptor desc = {
        DCE_OPCODE_MEMCMP,
        0,
        bitmask,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        DATA_SIZE,
        (uint64_t)src2,0,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
}
static void memcmp_test(int fd, uint64_t * comp, bool bitmask) {
    uint8_t * src = calloc(DATA_SIZE, sizeof(uint8_t));
    uint8_t * src2 = calloc(DATA_SIZE, sizeof(uint8_t));
    for (int i = 0; i < DATA_SIZE; i++) src[i] = (i % 16);
    for (int i = 0; i < DATA_SIZE; i++) src2[i] = ~src[i];
    printf("src: ");
    for (int i = 0; i < DATA_SIZE; i++) {printf("%x", src[i]);} printf("\n");
    printf("src2: ");
    for (int i = 0; i < DATA_SIZE; i++) {printf("%x", src2[i]);} printf("\n");

    // char src2[DATA_SIZE]= "abcdefghi";
    *comp = 0;
    if (bitmask) {
        uint8_t * dest = calloc(DATA_SIZE, sizeof(uint8_t));
        printf("===============memcmp test===============\n");
        dce_memcmp(fd, src, src2, dest, comp, bitmask);
        printf("Dest: ");
        for (int i = 0; i < DATA_SIZE; i++) {printf("%x", dest[i]);} printf("\n");
        printf("================test ended================\n\n");
    } else {
        uint64_t dest = 0;
        printf("===============memcmp test===============\n");
        dce_memcmp(fd, src, src2, (char *)&dest, comp, bitmask);
        printf("Dest:0x%lx, completion: 0x%lx\n", dest, *comp);
        printf("================test ended================\n\n");
    }
}
static void dce_memset(int fd, char * dest, uint64_t pattern_low, uint64_t pattern_high, uint64_t * completion) {
    DCEDescriptor desc = {
        DCE_OPCODE_MEMSET,
        0,
        0,
        0,
        0,
        (uint64_t)dest,
        (uint64_t)completion,
        DATA_SIZE,
        pattern_low,pattern_high,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
}
static void memset_test(int fd, uint64_t * comp) {
    uint8_t * dest = calloc(DATA_SIZE, sizeof(uint8_t));;
    uint64_t pattern_low = 0x0001000100010001;
    uint64_t pattern_high = 0xf0f0f0f0f0f0f0f0;

    *comp = 0;
    printf("===============memcmp test===============\n");
    printf("Dest: ");
        for (int i = 0; i < DATA_SIZE; i++) {printf("%x", dest[i]);} printf("\n");
    dce_memset(fd, dest, pattern_low, pattern_high, comp);
    printf("Completion: 0x%lx\n", *comp);
    printf("Dest: ");
        for (int i = 0; i < DATA_SIZE; i++) {printf("%x", dest[i]);} printf("\n");
    printf("================test ended================\n\n");
    free(dest);
}

static void dce_load_key(int fd, uint64_t * key_addr, uint64_t index, uint64_t * completion) {
    *completion = 0;
    DCEDescriptor desc = {
        DCE_OPCODE_LOAD_KEY,
        0,
        0,
        0,
        (uint64_t)key_addr,
        (uint64_t)index,
        (uint64_t)completion,
        0,0,0,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void dce_clear_key(int fd, uint64_t index, uint64_t * completion) {
    *completion = 0;
    DCEDescriptor desc = {
        DCE_OPCODE_CLEAR_KEY,
        0,
        0,
        0,
        0,
        (uint64_t)index,
        (uint64_t)completion,
        0,0,0,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void dce_encrypt(int fd, char * src, char * dest, uint8_t key1, uint8_t key2, uint64_t * completion) {
    *completion = 0;
    uint64_t operand3 = 0;
    uint8_t * op3_ptr = (uint8_t *)&operand3;
    op3_ptr[1] = key2;
    op3_ptr[0] = key1;
    DCEDescriptor desc = {
        DCE_OPCODE_ENCRYPT,
        0,
        0,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        DATA_SIZE,0,operand3,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void dce_decrypt(int fd, char * src, char * dest, uint8_t key1, uint8_t key2, uint64_t * completion) {
    *completion = 0;
    uint64_t operand3 = 0;
    uint8_t * op3_ptr = (uint8_t *)&operand3;
    op3_ptr[1] = key2;
    op3_ptr[0] = key1;
    DCEDescriptor desc = {
        DCE_OPCODE_DECRYPT,
        0,
        0,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        DATA_SIZE,0,operand3,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void dce_compress_encrypt(int fd, char * src, char * dest,
                                 uint64_t dest_size, uint8_t key1, uint8_t key2,
                                 uint64_t * completion) {
    *completion = 0;
    uint64_t operand3 = 0;
    uint8_t * op3_ptr = (uint8_t *)&operand3;
    op3_ptr[1] = key2;
    op3_ptr[0] = key1;
    DCEDescriptor desc = {
        DCE_OPCODE_COMPRESS_ENCRYPT,
        1,
        8,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        DATA_SIZE,dest_size,operand3,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void dce_decrypt_decompress(int fd, char * src, char * dest,
                                 uint64_t src_size, uint8_t key1, uint8_t key2,
                                 uint64_t * completion) {
    *completion = 0;
    uint64_t operand3 = 0;
    uint8_t * op3_ptr = (uint8_t *)&operand3;
    op3_ptr[1] = key2;
    op3_ptr[0] = key1;
    DCEDescriptor desc = {
        DCE_OPCODE_DECRYPT_DECOMPRESS,
        1,
        9,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        src_size,DATA_SIZE,operand3,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void load_clear_key_test(int fd, uint64_t * comp) {
    uint64_t key1[4], key2[4];
    for (int i = 0; i < 4; i++) {
        if (i == 0) {
            key1[i] = 0x0001000100010001;
            key2[i] = 0xf0f0f0f0f0f0f0f0;
        }
        else{
            key1[i] = key2[i - 1] >> 1;
            key2[i] = key1[i - 1] << 1;
        }
    }

    uint8_t * src = calloc(DATA_SIZE, sizeof(uint8_t));
    for (int i = 0; i < DATA_SIZE; i++) src[i] = (i % 16);
    uint8_t * dest = calloc(DATA_SIZE, 2);
    uint8_t * src2 = calloc(DATA_SIZE, sizeof(uint8_t));

    *comp = 0;
    printf("===============load/clear key test===============\n");
    dce_load_key(fd, key1, 3, comp);
    dce_load_key(fd, key2, 5, comp);
    printf("===============encrypt test===============\n");
    printf("before encrypt:\n");
    // for (int i = 0; i < DATA_SIZE; i++) {printf("%x", (uint8_t)src[i]);} printf("\n");
    dce_encrypt(fd, src, dest, 5, 3, comp);
    printf("after encrypt:\n");
    // for (int i = 0; i < DATA_SIZE; i++) {printf("%x", (uint8_t)dest[i]);} printf("\n");
    // dce_clear_key(fd, 3, comp);
    printf("Completion: 0x%lx\n", *comp);
    printf("===============decrypt test===============\n");
    dce_decrypt(fd, dest, src2, 5, 3, comp);

    if(memcmp(src2, src, DATA_SIZE)) {
        printf("after decrypt::\n");
        for (int i = 0; i < DATA_SIZE; i++) {printf("%x", (uint8_t)src2[i]);} printf("\n");
        printf("ERROR: Encrypt/Decrypt mismatch!\n");
    } else {
        printf("Passed: Encrypt/Decrypt match!\n");
    }
    printf("Completion: 0x%lx\n", *comp);

    printf("===============compress-encrypt test===============\n");
    memset(dest, 0, DATA_SIZE);
    memset(src2, 0, DATA_SIZE);
    dce_compress_encrypt(fd, src, dest, 2 * DATA_SIZE, 5, 3, comp);
    int compressed_size = (*comp) & 0xffffffff;
    dce_decrypt_decompress(fd, dest, src2, compressed_size, 5, 3, comp);
    if(memcmp(src2, src, DATA_SIZE)) {
        // printf("src:\n");
        // for (int i = 0; i < DATA_SIZE; i++) {printf("%c", src[i]);} printf("\n");
        // printf("src2:\n");
        // for (int i = 0; i < DATA_SIZE; i++) {printf("%c", src2[i]);} printf("\n");
        printf("ERROR: Compress-encrypt/Decrypt-decompress mismatch!\n");
    }
    else {
        printf("Passed: Compress-encrypt/Decrypt-decompress match!\n");
    }
    printf("================test ended================\n\n");
}

static void dce_compress(int fd, char * src, char * dest, uint64_t dest_size, uint64_t * completion) {
    *completion = 0;
    DCEDescriptor desc = {
        DCE_OPCODE_COMPRESS,
        0,
        8,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        DATA_SIZE,
        dest_size,0,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void dce_decompress(int fd, char * src, char * dest, uint64_t src_size, uint64_t * completion) {
    *completion = 0;
    DCEDescriptor desc = {
        DCE_OPCODE_DECOMPRESS,
        0,
        8,
        0,
        (uint64_t)src,
        (uint64_t)dest,
        (uint64_t)completion,
        src_size,
        DATA_SIZE,0,0
    };
    print_descriptor(&desc);
    if(ioctl(fd, SUBMIT_DESCRIPTOR, &desc) < 0) {
        printf("ioctl failed and returned errno %s \n",strerror(errno));
    };
    while(*completion == 0) {}
}
static void compress_decompress_test(int fd, uint64_t * comp) {
    char * src = calloc(DATA_SIZE, sizeof(uint8_t));
    char * src2 = calloc(DATA_SIZE, sizeof(uint8_t));
    // compressed data may be larger
    char * dest = calloc(DATA_SIZE , 2);
    for (int i = 0; i < DATA_SIZE; i++) src[i] = ('a' + (i % 26));

    // char src2[DATA_SIZE]= "abcdefghi";
    *comp = 0;
    printf("===============compress test===============\n");
    dce_compress(fd, src, dest, DATA_SIZE * 2, comp);
    for (int i = 0; i < DATA_SIZE; i++) printf("%c", dest[i]);
    printf("\n");
    printf("Completion 0x%lx\n", *comp);
    int compressed_size = (*comp) & 0xffffffff;
    *comp = 0;

    printf("Dest:\n");
    for (int i = 0; i < compressed_size; i++) {printf("%c", dest[i]);} printf("\n");
    printf("===============decompress test===============\n");
    dce_decompress(fd, dest, src2, compressed_size, comp);

    if(memcmp(src2, src, DATA_SIZE)) {
        // printf("src:\n");
        // for (int i = 0; i < DATA_SIZE; i++) {printf("%c", src[i]);} printf("\n");
        // printf("src2:\n");
        // for (int i = 0; i < DATA_SIZE; i++) {printf("%c", src2[i]);} printf("\n");
        // for (int i = 0; i < DATA_SIZE; i++) {
        //     if (src[i] != src2[i]) {
        //         printf("Index %d, src: %c src2 %c\n", i, src[i], src2[i]);
        //     }
        // }
        printf("ERROR: Compress/Decompress mismatch!\n");
    }
    else {
        printf("Passed: Compress/Decompress match!\n");
    }
    printf("================test ended================\n\n");
    free(src);free(dest);
}

int main( void )
{
    int fd;
    uint64_t completion = 0;
    fd = open("/dev/dce", O_RDWR);
    if (fd < 0) {
        perror("open: ");
        return 1;
    }
    // // Memcpy
    // memcpy_test(fd, &completion);
    // // Memcmp
    // memcmp_test(fd, &completion, 0); // bitmask = false
    // memcmp_test(fd, &completion, 1); // bitmask = true
    // // Memset
    // memset_test(fd, &completion);
    // load / clear keys
    load_clear_key_test(fd, &completion);
    // compress / decompres
    compress_decompress_test(fd, &completion);
    close(fd);
    return 0;
}

