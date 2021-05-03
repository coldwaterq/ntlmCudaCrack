#include <stdio.h>
#include <thread>
#include <chrono>


//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476

#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

__global__ void
NTLM(unsigned int* hash, unsigned int* output, char ch)
{
    unsigned int ident = blockDim.z * blockIdx.z + threadIdx.x;

    // The hash will be prepared before going into cuda.
    unsigned int nt_buffer[16];
    memset(nt_buffer, 0, 16 * 4);
    // hardcoded to hashcat
    // result should be b4b9b02e6f09a9bd760f388b67351e2b
    nt_buffer[0] = (ident%90)+0x20 | ((ident/90)%90)+0x20 << 16;// attempt to bruteforce this value 0x610068;
    ident = ident / (90 * 90);
    nt_buffer[1] = (ident % 90) + 0x20 | ((ident / 90) % 90) + 0x20 << 16; // attempt to brute force this value 0x680073;
    nt_buffer[2] = (blockDim.x % 90) + 0x20 | ((blockDim.x / 90) % 90) + 0x20 << 16;//0x610063;
    int temp = blockDim.x / (90 * 90);
    nt_buffer[3] = (temp % 90) + 0x20 | ((temp / 90) % 90) + 0x20 << 16;//0x800074;
    nt_buffer[14] = 0x70;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // NTLM hash calculation
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    unsigned int a = INIT_A;
    unsigned int b = INIT_B;
    unsigned int c = INIT_C;
    unsigned int d = INIT_D;

    /* Round 1 */
    a += (d ^ (b & (c ^ d))) + nt_buffer[0]; a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + nt_buffer[1]; d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + nt_buffer[2]; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + nt_buffer[3]; b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))) + nt_buffer[4]; a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + nt_buffer[5]; d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + nt_buffer[6]; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + nt_buffer[7]; b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))) + nt_buffer[8]; a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + nt_buffer[9]; d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + nt_buffer[10]; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + nt_buffer[11]; b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))) + nt_buffer[12]; a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + nt_buffer[13]; d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + nt_buffer[14]; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + nt_buffer[15]; b = (b << 19) | (b >> 13);

    /* Round 2 */
    a += ((b & (c | d)) | (c & d)) + nt_buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + nt_buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + nt_buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + nt_buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);

    /* Round 3 */
    a += (d ^ c ^ b) + nt_buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + nt_buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + nt_buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + nt_buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);
    output[21] = hash[0];
    output[22] = hash[1];
    output[23] = hash[2] == c + INIT_C;
    output[24] = hash[3] == d + INIT_D;
    if (hash[0] == a + INIT_A &&
        hash[1] == b + INIT_B &&
        hash[2] == c + INIT_C &&
        hash[3] == d + INIT_D) {
        for (int i = 0; i < 16; i++) {
            output[i] = nt_buffer[i];
        }
        output[20] = 1;
    }
    return;
}

__global__ void
NTLM7(unsigned int* hash, unsigned int* output)
{
    // unsigned int ident = 712 * blockIdx.z + threadIdx.x; // blockDim.z wasn't working, so switched to hard coded.
    unsigned int nt_buffer_0 = ((blockIdx.z*(threadIdx.x/90)) % 90) + 0x20 | (blockIdx.z * (threadIdx.x / 90) / 90) + 0x20 << 16;// attempt to bruteforce this value 0x610068;
    unsigned int nt_buffer_1 = (blockIdx.y % 90) + 0x20 | (blockIdx.y / 90) + 0x20 << 16; // attempt to brute force this value 0x680073;
    unsigned int nt_buffer_2 = (blockIdx.x % 90) + 0x20 | (blockIdx.x / 90) + 0x20 << 16; //(blockDim.x % 90) + 0x20 | (blockDim.x / 90) + 0x20 << 16;//0x610063;
    unsigned int nt_buffer_3 = 0x800000 + (threadIdx.x%90)+0x20;// blockDim.y + 0x20;//0x800074;
    unsigned int nt_buffer_14 = 0x70;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // NTLM hash calculation
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    unsigned int a = INIT_A;
    unsigned int b = INIT_B;
    unsigned int c = INIT_C;
    unsigned int d = INIT_D;

    /* Round 1 */
    a += (d ^ (b & (c ^ d))) + nt_buffer_0; a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + nt_buffer_1; d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + nt_buffer_2; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + nt_buffer_3; b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))); a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))); d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))); c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))); b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))); a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))); d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))); c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))); b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))); a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))); d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + nt_buffer_14; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))); b = (b << 19) | (b >> 13);

    /* Round 2 */
    a += ((b & (c | d)) | (c & d)) + nt_buffer_0 + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + nt_buffer_1 + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + nt_buffer_2 + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer_14 + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + nt_buffer_3 + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + SQRT_2; b = (b << 13) | (b >> 19);

    /* Round 3 */
    a += (d ^ c ^ b) + nt_buffer_0 + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + nt_buffer_2 + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer_14 + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + nt_buffer_1 + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + nt_buffer_3 + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + SQRT_3; b = (b << 15) | (b >> 17);
    if (hash[0] == a &&
        hash[1] == b &&
        hash[2] == c &&
        hash[3] == d) {
        output[0] = nt_buffer_0;
        output[1] = nt_buffer_1;
        output[2] = nt_buffer_2;
        output[3] = nt_buffer_3;
        output[14] = nt_buffer_14;
        output[20] = 1;
    }
    return;
}

unsigned int* getHash(char* hash) {
    unsigned int* h_hash = (unsigned int*)malloc(4 * 4);
    // Verify that allocations succeeded
    if (h_hash == NULL)
    {
        fprintf(stderr, "Failed to allocate host memory!\n");
        exit(EXIT_FAILURE);
    }
    h_hash[0] = 0x2eb0b9b4;
    h_hash[1] = 0xbda9096f;
    h_hash[2] = 0x8b380f76;
    h_hash[3] = 0x2b1e3567;

    h_hash[0] -= INIT_A;
    h_hash[1] -= INIT_B;
    h_hash[2] -= INIT_C;
    h_hash[3] -= INIT_D;
    return h_hash;
}

int debug7Char(void) {
    // Error code to check return values for CUDA calls
    cudaError_t err = cudaSuccess;

    dim3 threadsPerBlock(1024, 1, 1);
    dim3 blocksPerGrid(8100,// 90*90
        8100,// 90*90
        737 // 90*90//(1024//90)+1=737
    );
    printf("threads x: %d, y: %d, z: %d\n", threadsPerBlock.x, threadsPerBlock.y, threadsPerBlock.z);
    printf("blocks x: %d, y: %d, z: %d\n", blocksPerGrid.x, blocksPerGrid.y, blocksPerGrid.z);

    // Allocate the device hash vector
    unsigned int* d_hash = NULL;
    err = cudaMalloc((void**)&d_hash, 4 * 4);

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device hash (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    // Allocate the device output vector
    size_t output_size = 21 * 4;
    unsigned int* output = NULL;
    err = cudaMalloc((void**)&output, output_size);

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device output (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    // allocate host memory
    unsigned int* h_output = (unsigned int*)malloc(output_size);

    // Verify that allocations succeeded
    if ( h_output == NULL)
    {
        fprintf(stderr, "Failed to allocate host memory!\n");
        exit(EXIT_FAILURE);
    }

    unsigned int* h_hash = getHash("b4b9b02e6f09a9bd760f388b67351e2b");

    printf("Copy input data from the host memory to the CUDA device\n");
    err = cudaMemcpy(d_hash, h_hash, 4 * 4, cudaMemcpyHostToDevice);

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector A from host to device (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    NTLM7<< <blocksPerGrid, threadsPerBlock >> > (d_hash, output);
    err = cudaGetLastError();

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to launch vectorAdd kernel (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    printf("waiting for results");
    cudaThreadSynchronize();

    // Copy the device result vector in device memory to the host result vector
    // in host memory.
    printf("Copy output data from the CUDA device to the host memory\n");
    err = cudaMemcpy(h_output, output, output_size, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy vector output from device to host (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    printf("test\n");
    for (int i = 0; i < 16; i++) {
        printf("%#010x", h_output[i]);
        printf(" %c %c\n", ((char*)h_output)[i * 4], ((char*)h_output)[i * 4 + 2]);
    }

    printf("Test PASSED\n");

    // Free device global memory
    err = cudaFree(d_hash);
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector A (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    err = cudaFree(output);

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device vector C (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    // Free host memory
    free(h_hash);
    free(h_output);

    printf("Done\n");
    return 0;
}

/**
 * Host main routine
 */
int
main(void)
{

    int dev_count;
    cudaGetDeviceCount(&dev_count);
    printf("num devices: %d\n", dev_count);


    cudaDeviceProp dev_prop;
    for (int i = 0; i < dev_count; i++) {
        cudaGetDeviceProperties(&dev_prop, i);
        printf("max threads per block: %d\n", dev_prop.maxThreadsPerBlock);
        printf("max block x dim: %d\n", dev_prop.maxThreadsDim[0]);
        printf("max block y dim: %d\n", dev_prop.maxThreadsDim[1]);
        printf("max block z dim: %d\n", dev_prop.maxThreadsDim[2]);
        printf("max grid x dim: %d\n", dev_prop.maxGridSize[0]);
        printf("max grid y dim: %d\n", dev_prop.maxGridSize[1]);
        printf("max grid z dim: %d\n", dev_prop.maxGridSize[2]);
    }

    return debug7Char();
}

