// This is an independent implementation of the encryption algorithm:   
//                                                                      
//         RIJNDAEL by Joan Daemen and Vincent Rijmen                   
//                                                                      
// which is a candidate algorithm in the Advanced Encryption Standard   
// programme of the US National Institute of Standards and Technology.  
//                                                                      
// Copyright in this implementation is held by Dr B R Gladman but I     
// hereby give permission for its free direct or derivative use subject 
// to acknowledgment of its origin and compliance with any conditions   
// that the originators of the algorithm place on its exploitation.     
//                                                                      
// Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     

//  Algorithm rijndael (rijndael.cpp)
//  128 bit key:
//  Key Setup:    223/1416 cycles (encrypt/decrypt)
//  Encrypt:       362 cycles =    70.7 mbits/sec
//  Decrypt:       367 cycles =    69.8 mbits/sec
//  Mean:          365 cycles =    70.2 mbits/sec
//  192 bit key:
//  Key Setup:    214/1660 cycles (encrypt/decrypt)
//  Encrypt:       442 cycles =    57.9 mbits/sec
//  Decrypt:       432 cycles =    59.3 mbits/sec
//  Mean:          437 cycles =    58.6 mbits/sec
//  256 bit key:
//  Key Setup:    287/1994 cycles (encrypt/decrypt)
//  Encrypt:       502 cycles =    51.0 mbits/sec
//  Decrypt:       506 cycles =    50.6 mbits/sec
//  Mean:          504 cycles =    50.8 mbits/sec
//  代码运行实例 http://ideone.com/r0Cmsx
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u1byte;
typedef unsigned long u4byte;

u1byte pow_tab[256];        //指数表
u1byte log_tab[256];        //对数表
u1byte sbx_tab[256];        //S盒
u1byte isb_tab[256];        //逆S盒子
u4byte rco_tab[ 10];        //轮常数
u4byte ft_tab[4][256];      //查S盒与列混合复合表
u4byte it_tab[4][256];      //查逆S盒与逆列混合复合表
u1byte tab_gen = 0;         //标记是否生成表
u4byte k_len = 0;           //密钥长，字为单位

#define LARGE_TABLES

#ifdef LARGE_TABLES
    u4byte fl_tab[4][256];   
    //S盒4字节大表，第二维表示表项值字节所处位置，其余3字节填0
    
    u4byte il_tab[4][256];
#endif

#define ff_mult(a, b)    \
            ((a) && (b) ? pow_tab[(log_tab[a] + log_tab[b]) % 255] : 0)
#define byte(x, i) (((x) >> ((i) << 3)) & 0x000000ff)
#define rotl(t, n) (((t) >> (32-n)) | ((t) << n))
#define rotr(t, n) (((t) << (32-n)) | ((t) >> n))

void gen_tabs(void)
{   
    u4byte  i, t;
    u1byte  p, q;   

    for(i = 0,p = 1; i < 256; ++i)      //生成对数表和指数表
    {
        pow_tab[i] = (u1byte)p; log_tab[p] = (u1byte)i;
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x01b : 0);
    }

    log_tab[1] = 0; p = 1;

    for(i = 0; i < 10; ++i)             //轮常数
    {
        rco_tab[i] = p; 
        p = (p << 1) ^ (p & 0x80 ? 0x1b : 0);
    }

    for(i = 0; i < 256; ++i)            //S盒子和逆S盒子
    {   
        p = (i ? pow_tab[255 - log_tab[i]] : 0); q = p; 
        q = (q >> 7) | (q << 1); p ^= q; 
        q = (q >> 7) | (q << 1); p ^= q; 
        q = (q >> 7) | (q << 1); p ^= q; 
        q = (q >> 7) | (q << 1); p ^= q ^ 0x63; 
        sbx_tab[i] = p; isb_tab[p] = (u1byte)i;
    }

    for(i = 0; i < 256; ++i)
    {
        p = sbx_tab[i]; 

#ifdef  LARGE_TABLES
        t = p; 
        fl_tab[0][i] = t;
        fl_tab[1][i] = rotl(t,  8);
        fl_tab[2][i] = rotl(t, 16);
        fl_tab[3][i] = rotl(t, 24);
#endif

        t = ((u4byte)ff_mult(2, p)) |
            ((u4byte)p <<  8) |
            ((u4byte)p << 16) |
            ((u4byte)ff_mult(3, p) << 24);        
        ft_tab[0][i] = t;
        ft_tab[1][i] = rotl(t,  8);
        ft_tab[2][i] = rotl(t, 16);
        ft_tab[3][i] = rotl(t, 24);
        p = isb_tab[i]; 

#ifdef  LARGE_TABLES        
        t = p; 
        il_tab[0][i] = t; 
        il_tab[1][i] = rotl(t,  8); 
        il_tab[2][i] = rotl(t, 16); 
        il_tab[3][i] = rotl(t, 24);
#endif 

        t = ((u4byte)ff_mult(14, p)) |
            ((u4byte)ff_mult( 9, p) <<  8) |
            ((u4byte)ff_mult(13, p) << 16) |
            ((u4byte)ff_mult(11, p) << 24);        
        it_tab[0][i] = t; 
        it_tab[1][i] = rotl(t,  8); 
        it_tab[2][i] = rotl(t, 16); 
        it_tab[3][i] = rotl(t, 24); 
    }
    tab_gen = 1;
}

#ifdef LARGE_TABLES
//ls_box实现按字查S盒子
#define ls_box(x)                \
    ( fl_tab[0][byte(x, 0)] ^    \
      fl_tab[1][byte(x, 1)] ^    \
      fl_tab[2][byte(x, 2)] ^    \
      fl_tab[3][byte(x, 3)] )

#define f_rl(bo, bi, n, k)                          \
    bo[n] =  fl_tab[0][byte(bi[n],0)] ^             \
             fl_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
             fl_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             fl_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

#define i_rl(bo, bi, n, k)                          \
    bo[n] =  il_tab[0][byte(bi[n],0)] ^             \
             il_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
             il_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             il_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

#else

#define ls_box(x)                            \
    ((u4byte)sbx_tab[byte(x, 0)] <<  0) ^    \
    ((u4byte)sbx_tab[byte(x, 1)] <<  8) ^    \
    ((u4byte)sbx_tab[byte(x, 2)] << 16) ^    \
    ((u4byte)sbx_tab[byte(x, 3)] << 24)

#define f_rl(bo, bi, n, k)                                      \
    bo[n] = (u4byte)sbx_tab[byte(bi[n],0)] ^                    \
        rotl(((u4byte)sbx_tab[byte(bi[(n + 1) & 3],1)]),  8) ^  \
        rotl(((u4byte)sbx_tab[byte(bi[(n + 2) & 3],2)]), 16) ^  \
        rotl(((u4byte)sbx_tab[byte(bi[(n + 3) & 3],3)]), 24) ^ *(k + n)

#define i_rl(bo, bi, n, k)                                      \
    bo[n] = (u4byte)isb_tab[byte(bi[n],0)] ^                    \
        rotl(((u4byte)isb_tab[byte(bi[(n + 3) & 3],1)]),  8) ^  \
        rotl(((u4byte)isb_tab[byte(bi[(n + 2) & 3],2)]), 16) ^  \
        rotl(((u4byte)isb_tab[byte(bi[(n + 1) & 3],3)]), 24) ^ *(k + n)

#endif

//实现*0x02的功能，即*x
#define star_x(x) (((x) & 0x7f7f7f7f) << 1) ^ ((((x) & 0x80808080) >> 7) * 0x1b)

//逆列混合
#define imix_col(y,x)       \
    u   = star_x(x);        \
    v   = star_x(u);        \
    w   = star_x(v);        \
    t   = w ^ (x);          \
   (y)  = u ^ v ^ w;        \
   (y) ^= rotr(u ^ t,  8) ^ \
          rotr(v ^ t, 16) ^ \
          rotr(t,24)

#define loop4(i)                                    \
{   t = ls_box(rotr(t,  8)) ^ rco_tab[i];           \
    t ^= e_key[4 * i];     e_key[4 * i + 4] = t;    \
    t ^= e_key[4 * i + 1]; e_key[4 * i + 5] = t;    \
    t ^= e_key[4 * i + 2]; e_key[4 * i + 6] = t;    \
    t ^= e_key[4 * i + 3]; e_key[4 * i + 7] = t;    \
}

#define loop6(i)                                    \
{   t = ls_box(rotr(t,  8)) ^ rco_tab[i];           \
    t ^= e_key[6 * i];     e_key[6 * i + 6] = t;    \
    t ^= e_key[6 * i + 1]; e_key[6 * i + 7] = t;    \
    t ^= e_key[6 * i + 2]; e_key[6 * i + 8] = t;    \
    t ^= e_key[6 * i + 3]; e_key[6 * i + 9] = t;    \
    t ^= e_key[6 * i + 4]; e_key[6 * i + 10] = t;   \
    t ^= e_key[6 * i + 5]; e_key[6 * i + 11] = t;   \
}

#define loop8(i)                                    \
{   t = ls_box(rotr(t,  8)) ^ rco_tab[i];           \
    t ^= e_key[8 * i];     e_key[8 * i + 8] = t;    \
    t ^= e_key[8 * i + 1]; e_key[8 * i + 9] = t;    \
    t ^= e_key[8 * i + 2]; e_key[8 * i + 10] = t;   \
    t ^= e_key[8 * i + 3]; e_key[8 * i + 11] = t;   \
    t  = e_key[8 * i + 4] ^ ls_box(t);              \
    e_key[8 * i + 12] = t;                          \
    t ^= e_key[8 * i + 5]; e_key[8 * i + 13] = t;   \
    t ^= e_key[8 * i + 6]; e_key[8 * i + 14] = t;   \
    t ^= e_key[8 * i + 7]; e_key[8 * i + 15] = t;   \
}

u4byte e_key[64];
u4byte d_key[64];

void set_key(const u1byte in_key[], const u4byte key_len)
{   
    u4byte  i, t, u, v, w;

    if(!tab_gen)
        gen_tabs();

    k_len = (key_len + 31) / 32;
    /*
    e_key[0] = u4byte_in(in_key     ); 
    e_key[1] = u4byte_in(in_key +  4);
    e_key[2] = u4byte_in(in_key +  8); 
    e_key[3] = u4byte_in(in_key + 12);
    */
    /*e_key[0] = *(u4byte *)(&in_key[0]);
    e_key[1] = *(u4byte *)(&in_key[4]);
    e_key[2] = *(u4byte *)(&in_key[8]);
    e_key[3] = *(u4byte *)(&in_key[12]);*/
    memcpy(&e_key[0], in_key,      4);
    memcpy(&e_key[1], in_key +  4, 4);
    memcpy(&e_key[2], in_key +  8, 4);
    memcpy(&e_key[3], in_key + 12, 4);

    switch(k_len)
    {
        case 4: t = e_key[3];
                for(i = 0; i < 10; ++i) 
                    loop4(i);
                break;

        case 6: //e_key[4] = u4byte_in(in_key + 16); t = e_key[5] = u4byte_in(in_key + 20);
                memcpy(&e_key[4], in_key + 16, 4); memcpy(&e_key[5], in_key + 20, 4); t = e_key[5];
                for(i = 0; i < 8; ++i) 
                    loop6(i);
                break;

        case 8: //e_key[4] = u4byte_in(in_key + 16); e_key[5] = u4byte_in(in_key + 20);
                //e_key[6] = u4byte_in(in_key + 24); t = e_key[7] = u4byte_in(in_key + 28);
                memcpy(&e_key[4], in_key + 16, 4); memcpy(&e_key[5], in_key + 20, 4); 
                memcpy(&e_key[6], in_key + 24, 4); memcpy(&e_key[7], in_key + 28, 4); t = e_key[7];
                for(i = 0; i < 7; ++i) 
                    loop8(i);
                break;
    }

    d_key[0] = e_key[0]; d_key[1] = e_key[1];
    d_key[2] = e_key[2]; d_key[3] = e_key[3];

    for(i = 4; i < 4 * k_len + 24; ++i)
    {
        imix_col(d_key[i], e_key[i]);
    }

    return;
}

#define f_rn(bo, bi, n, k)                          \
    bo[n] =  ft_tab[0][byte(bi[n],0)] ^             \
             ft_tab[1][byte(bi[(n + 1) & 3],1)] ^   \
             ft_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             ft_tab[3][byte(bi[(n + 3) & 3],3)] ^ *(k + n)

//每一轮
#define f_nround(bo, bi, k) \
    f_rn(bo, bi, 0, k);     \
    f_rn(bo, bi, 1, k);     \
    f_rn(bo, bi, 2, k);     \
    f_rn(bo, bi, 3, k);     \
    k += 4

//最后一轮
#define f_lround(bo, bi, k) \
    f_rl(bo, bi, 0, k);     \
    f_rl(bo, bi, 1, k);     \
    f_rl(bo, bi, 2, k);     \
    f_rl(bo, bi, 3, k)

void encrypt(const u1byte in_blk[16], u1byte out_blk[16])
{   
    u4byte  b0[4], b1[4], *kp;

    //b0[0] = u4byte_in(in_blk     ) ^ e_key[0]; 
    //b0[1] = u4byte_in(in_blk +  4) ^ e_key[1];
    //b0[2] = u4byte_in(in_blk +  8) ^ e_key[2]; 
    //b0[3] = u4byte_in(in_blk + 12) ^ e_key[3];    
    b0[0] = *(u4byte *)(&in_blk[0]) ^ e_key[0];
    b0[1] = *(u4byte *)(&in_blk[4]) ^ e_key[1];
    b0[2] = *(u4byte *)(&in_blk[8]) ^ e_key[2];
    b0[3] = *(u4byte *)(&in_blk[12]) ^ e_key[3];

    kp = e_key + 4;

    if(k_len > 6)
    {
        f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    }

    if(k_len > 4)
    {
        f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    }

    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_nround(b0, b1, kp);
    f_nround(b1, b0, kp); f_lround(b0, b1, kp);

    //u4byte_out(out_blk,      b0[0]); u4byte_out(out_blk +  4, b0[1]);
    //u4byte_out(out_blk +  8, b0[2]); u4byte_out(out_blk + 12, b0[3]);
    memcpy(out_blk     , &b0[0], 4);memcpy(out_blk +  4, &b0[1], 4);
    memcpy(out_blk +  8, &b0[2], 4);memcpy(out_blk + 12, &b0[3], 4);
}

#define i_rn(bo, bi, n, k)                          \
    bo[n] =  it_tab[0][byte(bi[n],0)] ^             \
             it_tab[1][byte(bi[(n + 3) & 3],1)] ^   \
             it_tab[2][byte(bi[(n + 2) & 3],2)] ^   \
             it_tab[3][byte(bi[(n + 1) & 3],3)] ^ *(k + n)

#define i_nround(bo, bi, k) \
    i_rn(bo, bi, 0, k);     \
    i_rn(bo, bi, 1, k);     \
    i_rn(bo, bi, 2, k);     \
    i_rn(bo, bi, 3, k);     \
    k -= 4

#define i_lround(bo, bi, k) \
    i_rl(bo, bi, 0, k);     \
    i_rl(bo, bi, 1, k);     \
    i_rl(bo, bi, 2, k);     \
    i_rl(bo, bi, 3, k)

void decrypt(const u1byte in_blk[16], u1byte out_blk[16])
{   
    u4byte  b0[4], b1[4], *kp;
    
    //b0[0] = u4byte_in(in_blk     ) ^ e_key[4 * k_len + 24]; 
    //b0[1] = u4byte_in(in_blk +  4) ^ e_key[4 * k_len + 25];
    //b0[2] = u4byte_in(in_blk +  8) ^ e_key[4 * k_len + 26]; 
    //b0[3] = u4byte_in(in_blk + 12) ^ e_key[4 * k_len + 27];    
    b0[0] = *(u4byte *)(&in_blk[0]) ^ e_key[4 * k_len + 24];
    b0[1] = *(u4byte *)(&in_blk[4]) ^ e_key[4 * k_len + 25];
    b0[2] = *(u4byte *)(&in_blk[8]) ^ e_key[4 * k_len + 26];
    b0[3] = *(u4byte *)(&in_blk[12])^ e_key[4 * k_len + 27];
    
    kp = d_key + 4 * (k_len + 5);

    if(k_len > 6)
    {
        i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    }

    if(k_len > 4)
    {
        i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    }

    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_nround(b0, b1, kp);
    i_nround(b1, b0, kp); i_lround(b0, b1, kp);

    //u4byte_out(out_blk,     b0[0]); u4byte_out(out_blk +  4, b0[1]);
    //u4byte_out(out_blk + 8, b0[2]); u4byte_out(out_blk + 12, b0[3]);    
    memcpy(out_blk     , &b0[0], 4);memcpy(out_blk +  4, &b0[1], 4);
    memcpy(out_blk +  8, &b0[2], 4);memcpy(out_blk + 12, &b0[3], 4);
}

void prtBytes(FILE *fp,u1byte byte16[],int nbit)
{
    int i=0;
    for(i=0;i<(nbit/8);i++)
    {
        fprintf(fp,"%02x",byte16[i]);
    }
    fprintf(fp,"\n");
}

int main(void)
{    
    u1byte m[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    u1byte c[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    u1byte key1[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    u1byte key2[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x63, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68};
    u1byte key3[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x63, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x2b, 0x28, 0xd2, 0xab, 0x15, 0x09, 0x4f};
//  u1byte key[] = {0x63, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x2b, 0x28, 0xd2, 0xab, 0x15, 0x09, 0x4f};

    printf("128m  ："); prtBytes(stdout,m,128); printf("\n");
    printf("128key："); prtBytes(stdout,key1,128); printf("\n");
    set_key(key1, 128);
    encrypt(m,c);
    printf("c     ："); prtBytes(stdout,c,128);
    decrypt(c,m);
    printf("m     ："); prtBytes(stdout,m,128);

    printf("192key："); prtBytes(stdout,key2,192); printf("\n");
    set_key(key2, 192);
    encrypt(m,c);
    printf("c     ："); prtBytes(stdout,c,128);
    decrypt(c,m);
    printf("m     ："); prtBytes(stdout,m,128);

    printf("256key："); prtBytes(stdout,key3,256); printf("\n");
    set_key(key3, 256);
    encrypt(m,c);
    printf("c     ："); prtBytes(stdout,c,128);
    decrypt(c,m);
    printf("m     ："); prtBytes(stdout,m,128);

    return 0;
}
