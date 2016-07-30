/*
** RSA加解密算法
** 内含大整数(1024bit整数，普通计算机字长64bit)处理常见算法
** 算法运行实例 http://ideone.com/08pS4S
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

typedef unsigned char  u1byte;
typedef unsigned short u2byte;
typedef unsigned long  u4byte;

#define U1K_FMT 0x10
#define U1K_NOE 0x20
#define U2K_FMT 0x30
#define U2K_NOE 0x40

typedef struct {
    u2byte len;
    u4byte val[33];            // 32+1 避免越界
}u1kbit;

typedef struct {
    u2byte len;
    u4byte val[64];
}u2kbit;

typedef struct {
    u1kbit quot;
    u1kbit rem;
}u1kdiv;

//=============字节操作相关函数，即主要操作数是字节指针================
u2byte getRelLen(u1byte *a, u2byte n);            //获取a的实际长度，n表示的a的最大长度
u1byte isZero(u1byte *a, int n);                //判断n字节的a数据是否全是0
int bytecmp(u1byte *a, u1byte *b, int n);        //比较n字节的a和b，a>b返回1，a<b返回-1，a=b返回0
void halfBytes(u1byte *a, int n);                //a = a/2，通过逐个字节移位计算
void doubleBytes(u1byte *a, int n);                //a = 2*a，通过逐个字节移位计算

void wordAddin(u1byte *dst, u4byte v);            //将字v 加入dst所指存储区，直到v为零或者没有进位
void addin(u1byte *a, u1byte *b, int n);        //a = a + b， n字节的数据b加到a中
void wordSubout(u1byte *dst, u4byte v);            //dst中减去字v 直到v为零或者没有借位
u1byte subout(u1byte *a, int starti, u1byte *b, int n);    //从a中减去n字节的b，starti指示的是a开始的首字节（实现a的循环字节移位）

void monPro_FIOS(u1byte *c, u1byte *a, u1byte *b, u1byte *n, int s);
// product c = a * b * r^-1 mod n  FIOS, r = (2^8)^s, n为奇数，注意此处的n必须为奇数！！！！！！！

//=============大数运算相关=========================================
u1byte add(u1kbit *c, u1kbit *a, u1kbit *b);            //c = a + b， 两个1kbit的数据相加，结果存在c，过程中会对c清零
void mul(u2kbit *c, u1kbit *a, u1kbit *b);                //c = a * b 计算时会对c进行置零
void wordMul(u2kbit *c, u1kbit *a, u4byte b);            //c = a * b 其中b是字
int inv(u1kbit *invx, u1kbit *x);                        //计算x^-1，保留1024位有效数字
void bigIntDiv(u1kdiv *c, u2kbit *a, u1kbit *b);        //大整数数值除法，结果为商和余数 a = c->quot * b + c->rem

long eeInv(long n, long b);                // 扩展的欧几里德算法求逆  t = (b^-1) mod n， 数的范围应该在 1~0x7fffffff
u4byte mInv(u4byte x, u4byte b);        // 求x的逆，x必须是奇数，且b是2的幂 t = (x^-1) mod b

void transResidue(u1kbit *ar, u1kbit *a, u1kbit *n);    //转换a的剩余类，结果ar = a*r mod n
void exGcd(u1kbit *rr, u1kbit * e, u1kbit *phi);        //扩展的欧几里德算法求逆，中途对求商取余的中间值做了转换，避免频繁的大整数除法r = (e^-1) mod phi
void monInverse(u1kbit *rr, u1kbit *b, u1kbit *a);        //Montgomery模逆运算，必须保证a是奇数 rr = (b^-1*2^n) mod a, n表示a的位数
void modInv(u1kbit *r, u1kbit * e, u1kbit *phi);        //模逆，phi是奇数采用Montgomery模逆，偶数则采用扩展的欧几里德算法 r = (e^-1) mod phi
void monExp(u1kbit *r, u1kbit *a, u1kbit *e, u1kbit *n);//模幂运算，采用Montgomery模乘实现 r = a^e mod n

//==================辅助函数=======================================
void strToUbit(u1kbit *a, char * str);    //辅助函数，将字符串str表示的16进制数存入1kbit的a中，注意最大1024位，即str最长256
void prtBigInt(void *a, int op);        //辅助函数，将1k或2k数据格式化或非格式化输出，模式由op控制


u1byte add(u1kbit *c, u1kbit *a, u1kbit *b)        //c = a + b， 两个1kbit的数据相加，结果存在c，过程中会对c清零
{
    int i = 0;
    u2byte *p = NULL, *q = NULL, *r = NULL;
    u4byte t = 0;

    memset(c, 0, sizeof(u1kbit));

    p = (u2byte *)(a->val);    q = (u2byte *)(b->val); r = (u2byte *)(c->val);

    for (i = 0; i<63; i++)
    {
        *(u4byte *)(&r[i]) += (u4byte)p[i] + (u4byte)q[i];
    }
    t = (u4byte)p[i] + (u4byte)q[i] + r[i];
    r[i] = (u2byte)(t & 0x0000ffff);            //不能直接加入r[i] 可能产生进位

    return (t >> 16) & 0x00000001;
}

void addin(u1byte *a, u1byte *b, int n)        //a = a + b， n字节的数据b加到a中
{
    int i = 0;
    u4byte t = 0;
    u1byte *r = NULL;
    r = (u1byte *)malloc(n); memset(r, 0, n);

    for (i = 0; i<n - 1; i++)                        //此处可优化
    {
        *(u2byte *)(&r[i]) += (u2byte)a[i] + (u2byte)b[i];
    }
    t = (u2byte)a[i] + (u2byte)b[i] + r[i];        //此处对于a中原来就有的数据应做加入处理！！
    r[i] = (u1byte)(t & 0x00ff);
    wordAddin(&r[n], t >> 8);
    memcpy(a, r, n);
    //return (t >> 8) & 0x0001;
}

void wordAddin(u1byte *dst, u4byte v)            //将字v 加入dst所指存储区，直到v为零或者没有进位
{
    u4byte t = 0;
    int i = 0;
    do {
        t = dst[i] + (v & 0x00ff) + t;
        dst[i] = (u1byte)(t & 0x00ff);
        t = t >> 8;    v = v >> 8;    i++;
    } while (0 != v || 0 != t);
}

u1byte subout(u1byte *a, int starti, u1byte *b, int n)    //从a中减去n字节的b，starti指示的是a开始的首字节（实现a的循环字节移位）
{
    int i = 0;
    u2byte borrow = 0x100, t = 0;

    for (i = 0; i < n; i++)
    {
        t = borrow + a[starti] - b[i] - t;
        a[starti] = t & 0x00ff;
        t = ((t >> 8) ^ 0x0001);
        starti = (starti + 1) % n;
    }
    return t;
}

void wordSubout(u1byte *dst, u4byte v)            //dst中减去字v 直到v为零或者没有借位
{
    int i = 0;
    u2byte borrow = 0x100, t = 0;

    do {
        t = borrow + dst[i] - (v & 0x00ff) - t;
        dst[i] = (u1byte)(t & 0x00ff);
        t = ((t >> 8) ^ 0x0001); v = v >> 8; i++;
    } while (0 != v || 0 != t);
}

long eeInv(long n, long b)                // 扩展的欧几里德算法求逆  t = (b^-1) mod n， 数的范围应该在 1~0x7fffffff
{
    long x = 0, y = 1, t1 = 0, t2 = 0, t = n;
    if (n <= b) {
        return -1;
    }
    while (b > 0)
    {
        t1 = n / b;
        t2 = n - t1 * b;
        n = b; b = t2;
        t2 = x - t1 * y;
        x = y; y = t2;
    }
    if (1 == n) {
        return x < 0 ? x + t : x;
    }
    else {
        return -1;
    }
}

u4byte mInv(u4byte x, u4byte b)        // 求x的逆，x必须是奇数，且b是2的幂 t = (x^-1) mod b
{
    u1byte lgb = 0; u4byte t = b, i = 0;
    while ((t = t >> 1) && ++lgb);
    if ((0x01l << lgb) != b) { printf("b is not a power of 2!");return -1; }
    t = 1;
    for (i = 2;i <= lgb;i++)
    {
        if (((x*t) & (0x7fffffffl >> (31 - i))) > (0x01l << (i - 1)))
        {
            t = t + (0x01l << (i - 1));
        }
    }
    return t;
}

u2byte nd = 0;

void monPro_FIOS(u1byte *c, u1byte *a, u1byte *b, u1byte *n, int s)
// product c = a * b * r^-1 mod n  FIOS, r = (2^8)^s, n为奇数，注意此处的n必须为奇数！！！！！！！
{
    int i = 0, j = 0;
    u1byte *t = NULL, m = 0;
    u2byte tmp = 0, borrow = 0x100;

    if (0 == nd || NULL != n)
    {
        nd = mInv(n[0], 256);
        nd = 256 - nd;
    }

    t = (u1byte *)malloc(s + 2);
    memset(t, 0, s + 2);

    for (i = 0;i < s;i++)
    {
        tmp = t[0] + a[0] * b[i];
        wordAddin(&t[1], tmp >> 8);
        m = ((tmp & 0x00ff) * nd) & 0x00ff;
        tmp = (tmp & 0x00ff) + m * n[0];
        for (j = 1;j < s;j++)
        {
            tmp = t[j] + a[j] * b[i] + (tmp >> 8);
            wordAddin(&t[j + 1], tmp >> 8);
            tmp = (tmp & 0x00ff) + m * n[j];
            t[j - 1] = (tmp & 0x00ff);
        }
        tmp = t[s] + (tmp >> 8);
        t[s - 1] = tmp & 0x00ff;
        t[s] = t[s + 1] + (tmp >> 8);
        t[s + 1] = 0;
    }
    borrow = 0x100; tmp = 0;                        ////初始化！！！！！！！！！！
    if (bytecmp(t, n, s + 2) > -1)
    {
        for (i = 0; i < s; i++)
        {
            tmp = borrow + t[i] - n[i] - tmp;
            c[i] = tmp & 0x00ff;
            tmp = ((tmp >> 8) ^ 0x0001);
        }
    }
    else
    {
        memcpy(c, t, s);
    }

    free(t);
}

void mul(u2kbit *c, u1kbit *a, u1kbit *b)        //c = a * b 计算时会对c进行置零
{
    u1byte *p = NULL, *q = NULL, *r = NULL;
    int i = 0, j = 0, k = 0, m = 0;
    u4byte t = 0;

    memset(c, 0, sizeof(u2kbit));
    p = (u1byte *)(a->val); q = (u1byte *)(b->val); r = (u1byte *)(c->val);

    k = m = 0;
    for (i = 0; i<126; i++)
    {
        wordAddin(&r[k], p[i] * q[i]);
        for (j = i + 1; j<128; j++)
        {
            wordAddin(&r[k + (++m)], p[j] * q[i] + p[i] * q[j]);
        }
        k += 2; m = 0;
    }
    t = t + p[i] * q[i] + r[k]; r[k] = (u1byte)(t & 0x00ff); t = (t >> 8) & 0x00ff;
    t = t + p[i] * q[i + 1] + p[i + 1] * q[i] + r[k + 1];    //可能产生跨字节进位
    r[k + 1] = (u1byte)(t & 0x00ff); t = t >> 8;

    k += 2; i++;
    t = t + p[i] * q[i] + r[k]; r[k] = (u1byte)(t & 0x00ff);
    r[k + 1] = (u1byte)((t >> 8) & 0x00ff);
}

void wordMul(u2kbit *c, u1kbit *a, u4byte b)    //c = a * b 其中b是字 
{
    u1byte *p = NULL, *q = NULL, *r = NULL;
    int i = 0, j = 0;

    memset(c, 0, sizeof(u2kbit));
    p = (u1byte *)(a->val); q = (u1byte *)(&b); r = (u1byte *)(c->val);
    for (i = 0; i < 4; i++)                        //此处循环可优化
    {
        for (j = 0; j < 128; j++)
        {
            wordAddin(&r[i + j], p[j] * q[i]);
        }
    }
}

u2byte getRelLen(u1byte *a, u2byte n)            //获取a的实际长度，n表示的a的最大长度
{
    while ((0 == a[n - 1]) && (--n));
    return n;
}

//计算x^-1，保留1024位有效数字
int inv(u1kbit *invx, u1kbit *x)                //x^-1 * 2^y = 0.10000001010110.....
{
    u1byte *p = NULL, *r = NULL, d = 0, *tempa = NULL, *tempb = NULL;
    //tempa - tempb
    int i = 0, j = 0, dc = 0, si = 0;
    u2byte quot = 1;
    u4byte dd = 0, t = 0;

    p = (u1byte *)(x->val); r = (u1byte *)(invx->val);
    x->len = getRelLen(p, 128);                //注意x->len初始化要在temp分配内存之前!!

    memset(invx, 0, sizeof(u1kbit));
    tempa = (u1byte *)malloc(x->len + 1);
    memset(tempa, 0, x->len + 1);
    tempb = (u1byte *)malloc(x->len + 1);
    memset(tempb, 0, x->len + 1);

    //1.提取x的头8位（高位为1）作为估商的除数, 并记录第一个1移到最高位的移动位数
    t = (x->len > 1) ? *((u2byte *)(&p[x->len - 2])) : p[x->len - 1];
    if (0 == t) { printf("divisor is 0 !"); return 0; }
    dc = 0;
    while (!(t & 0x8000))
    {
        t = t << 1;
        dc++;
    }
    dc = dc > 7 ? dc - 8 : dc;
    d = (u1byte)((t >> 8) & 0x00ff);
    //2.提取被除数1的前16位, 初始为0x8000
    dd = 0x8000; si = 0;
    tempa[x->len] = (0x80 >> dc);

    for (i = 127; i >= 0; i--)
    {
        //3.计算估商
        quot = dd / (d + 1);
        if (i < 127) {
            //r[i+1] += (quot >> 8) & 0x00ff;
            wordAddin(&(r[i]), quot);
        }
        else {
            r[i] = quot & 0x00ff;
        }
        //4.估商乘以x
        t = 0;
        for (j = 0; j<x->len; j++)
        {
            t = quot * p[j] + t;
            tempb[j] = t & 0x00ff;
            t = t >> 8;
        }
        tempb[j] = t & 0x00ff;

        //5.用000000 （第一个字节80>> x最高位0的个数）减去4.得的结果

        subout(tempa, si, tempb, x->len + 1);

        //估商小了进行校正
        while (0 != tempa[(si + x->len) % (x->len + 1)])
        {
            quot++;
            //(*(u2byte *)(&r[i]))++;
            wordAddin(&(r[i]), 1);
            /////////////////////////////////////////////
            p[x->len] = 0; //数组越界！！！！！！！！！！
                           ////////////////////////////////////////////
            subout(tempa, si, x->val, x->len + 1);
        }
        //2.提取被减掉后数的前16位有效数字
        si = (x->len + 1 + si - 2) % (x->len + 1);
        t = ((u4byte)tempa[si] << 16) & 0xff0000;
        t |= ((u4byte)tempa[(x->len + 1 + si - 1) % (x->len + 1)] << 8) & 0x00ff00;
        t |= tempa[(x->len + 1 + si - 2) % (x->len + 1)];
        dd = (t >> (8 - dc)) & 0x00ffff;
        si = (si + 1) % (x->len + 1);
    }
    quot = dd / (d + 1);
    r[i + 1] += (quot >> 8) & 0x00ff;
    free(tempa); free(tempb);
    return (x->len * 8 - dc);
}

//大整数数值除法，结果为商和余数
void bigIntDiv(u1kdiv *c, u2kbit *a, u1kbit *b)        //a = c->quot * b + c->rem
{
    u1kbit invb;
    u1byte *p = NULL, *q = NULL, *temp = NULL, *r = NULL;
    int i = 0, m = 0, n = 0, j = 0, k = 0, y = 0;
    u4byte t = 0;
    u2kbit tt;

    memset(&invb, 0, sizeof(u1kbit));
    memset(&(c->quot), 0, sizeof(u1kbit));
    memset(&(c->rem), 0, sizeof(u1kbit));
    memset(&tt, 0, sizeof(u2kbit));

    p = (u1byte *)(a->val); q = (u1byte *)(invb.val); r = (u1byte *)(c->quot.val);

    n = inv(&invb, b);
    a->len = getRelLen(p, 256);
    m = a->len * 8;
    t = p[a->len - 1];
    while (!(t & 0x0080))
    {
        t = t << 1;
        m--; y++;
    }
    if (m > n) {
        m = m - n + 1;
        //if (m > 1024) { m = 1024; }        //m可以大于1024
        n = (int)ceil(m / 8.0) + 1;
        temp = (u1byte *)malloc(n);
        memset(temp, 0, n);
        //相乘计算中间值
        k = n - 2; t = 0;
        for (j = 1; j < n - 1; j++)
        {
            if (k > j) {
                t += p[a->len - 1 - k] * q[127 - j] + p[a->len - 1 - j] * q[127 - k];
            }
            else if (k == j) {
                t += p[a->len - 1 - k] * q[127 - j];
            }
            else { break; }
            k--;
        }
        t = t >> 8;
        wordAddin(&temp[0], t);        //防止估商过小，把前一位的进位计算出来存入temp[0]
        j = 0;
        for (i = 0; i<n - 1; i++)
        {
            k = n - 2 - i;
            for (j = 0; j<n - 1; j++)
            {
                if (k > j) {
                    wordAddin(&temp[i], p[a->len - 1 - k] * q[127 - j] + p[a->len - 1 - j] * q[127 - k]);
                }
                else if (k == j) {
                    wordAddin(&temp[i], p[a->len - 1 - k] * q[127 - j]);
                }
                else { break; }
                k--;
            }
        }
        //取计算结果的前m有效位
        i = getRelLen(temp, n);
        if (m > i * 8) {
            printf("error! m > really temp!");
            return;
        }
        else if (i * 8 == m) {
            memcpy(&(c->quot), temp, i);
        }
        else {
            j = i * 8 - m - y;                //实际bit尾部需要舍去j个比特
            k = j - ((j >> 3) << 3);        //实际bit转换到结果需要移位k位（字节偏移）
            for (y = 0; y<n - 2; y++)
            {
                r[y] = (*(u2byte *)(&temp[j / 8 + y]) >> k) & 0x00ff;
            }
            if (0 == (m & 0x07)) {
                r[y] = *(u2byte *)(&temp[j / 8 + y]) >> k;
            }
            else {
                r[y] = temp[j / 8 + y] >> k;
            }
            mul(&tt, b, &(c->quot));
            memcpy(c->rem.val, a->val, 129);        //估商可能过小，所以需要转存129字节的数据            
            subout(c->rem.val, 0, tt.val, 129);

            //rem > b 进行修正
            while (bytecmp(c->rem.val, b->val, 129) >= 0)
            {
                wordAddin(c->quot.val, 1);
                subout(c->rem.val, 0, b->val, 129);
            }
        }
    }
    else if (m == n) {
        n = (int)ceil(m / 8.0);
        t = bytecmp(a->val, b->val, n);
        if (1 == t)
        {
            c->quot.len = 1;
            c->quot.val[0] = 0x01;
            memcpy(c->rem.val, a->val, n);
            subout(c->rem.val, 0, b->val, n);
        }
        else if (0 == t)
        {
            c->quot.len = 1;
            c->quot.val[0] = 0x01;
        }
        else
        {
            (c->rem).len = a->len;
            memcpy(&(c->rem.val), a->val, n);
        }
    }
    else {
        (c->rem).len = a->len;
        memcpy(&(c->rem.val), a->val, 128);
    }
}

//转换a的剩余类，结果ar = a*r mod n
void transResidue(u1kbit *ar, u1kbit *a, u1kbit *n)            //ar = a*r mod n
{
    u2kbit tt; u1kdiv dd;
    memset(&tt, 0, sizeof(u2kbit)); memset(&dd, 0, sizeof(u1kdiv));
    //tt = a*r
    memcpy((((u1byte *)tt.val) + 128), a->val, 128);
    // mod n
    bigIntDiv(&dd, &tt, n);
    memcpy(ar->val, dd.rem.val, 128);
}

//扩展的欧几里德算法求逆，中途对求商取余的中间值做了转换，避免频繁的大整数除法
void exGcd(u1kbit *rr, u1kbit * e, u1kbit *phi)                    //r = (e^-1) mod phi
{
    u1byte *t, sig = 1, isContinue = 1, isChange = 0;
    u1kdiv dd; u2kbit u; u1kbit v, r, s;
    u4byte uu = 0, vv = 0, qq = 0, rm = 0;

    memset(&u, 0, sizeof(u2kbit)); memcpy(u.val, phi->val, 128); u.len = getRelLen(u.val, 128);
    memcpy(v.val, e->val, 128);
    memset(&s, 0, sizeof(u1kbit));
    memset(&r, 0, sizeof(u1kbit)); r.val[0] = 0x01;
    t = (u1byte *)malloc(128); memset(t, 0, 128);

    if (bytecmp(phi->val, e->val, 128) < 1) {
        printf("phi is equal to e!");
        return;
    }

    isContinue = !isZero(v.val, 128);
    while (isContinue)
    {
        if (!isChange && u.len < 5)
        {
            uu = u.val[0];
            vv = v.val[0];
            isChange = 1;
        }
        if (isChange)
        {
            qq = uu / vv;
            rm = uu - vv*qq;
            uu = vv; vv = rm;
            wordMul(&u, &r, qq);
            isContinue = (vv != 0);
        }
        else
        {
            bigIntDiv(&dd, &u, &v);
            mul(&u, &r, &dd.quot);
        }

        sig ^= 1;
        subout(s.val, 0, u.val, 128);
        memcpy(t, s.val, 128);
        memcpy(s.val, r.val, 128);
        memcpy(r.val, t, 128);

        if (!isChange)
        {
            u.val[32] = 0;
            memcpy(u.val, v.val, 128);
            memcpy(v.val, dd.rem.val, 128);
            isContinue = !isZero(v.val, 128);
        }
    }
    if (0x01 == uu || 0x01 == u.val[0])
    {
        if (1 == sig)
        {
            add(rr, &s, phi);
        }
        else
        {
            memcpy(rr->val, s.val, 128);
        }
    }
    else {
        printf("not relatively prime!");
    }
}

//判断n字节的a数据是否全是0
u1byte isZero(u1byte *a, int n)
{
    int i = 0;
    for (i = n - 1;i >= 0; i--)
    {
        if (0 != a[i])
        {
            return 0;
        }
    }
    return 1;
}

//比较n字节的a和b，a>b返回1，a<b返回-1，a=b返回0
int bytecmp(u1byte *a, u1byte *b, int n)
{
    int i = 0;
    for (i = n - 1;i >= 0; i--)
    {
        if (b[i] == a[i]) { continue; }
        if (a[i] > b[i]) {
            return 1;
        }
        else {
            return -1;
        }
    }
    return 0;
}

//a = a/2，通过逐个字节移位计算
void halfBytes(u1byte *a, int n)
{
    //u4byte *p = (u4byte *)a;
    int i = 0;
    for (i = 0;i < n - 1; i++)
    {
        a[i] = (a[i] >> 1) ^ ((a[i + 1] & 0x01) << 7);
    }
    a[i] = a[i] >> 1;
}

//a = 2*a，通过逐个字节移位计算
void doubleBytes(u1byte *a, int n)
{
    //u4byte *p = (u4byte *)a;
    int i = 0;
    for (i = n - 1;i >= 1; i--)
    {
        a[i] = (a[i] << 1) ^ (((a[i - 1] & 0x80) >> 7) & 0x01);
    }
    a[0] = a[0] << 1;
}

//Montgomery模逆运算，必须保证a是奇数
void monInverse(u1kbit *rr, u1kbit *b, u1kbit *a)                        //rr = (b^-1*2^n) mod a, n表示a的位数
// a is odd!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
{
    int n = 0, k = 0, i = 0;
    u1byte * p = NULL;
    u4byte t = 0;
    u1byte *u, *v, *s, *r;

    u = (u1byte *)malloc(128); memset(u, 0, 128);
    v = (u1byte *)malloc(128); memset(v, 0, 128);
    s = (u1byte *)malloc(128); memset(s, 0, 128);
    r = (u1byte *)malloc(128); memset(r, 0, 128);

    p = (u1byte *)(a->val);
    a->len = getRelLen(a->val, 128);
    n = a->len * 8;
    t = p[a->len - 1];
    while (!(t & 0x0080)) {
        t = t << 1;
        n--;
    }

    memcpy(rr->val, a->val, 128); memcpy(u, a->val, 128); memcpy(v, b->val, 128);
    s[0] = 0x01;

    while (!isZero(v, 128))
    {
        if ((u[0] & 0x01) ^ 0x01) {
            halfBytes(u, 128); doubleBytes(s, 128);
        }
        else if ((v[0] & 0x01) ^ 0x01)
        {
            halfBytes(v, 128); doubleBytes(r, 128);
        }
        else if (1 == bytecmp(u, v, 128))
        {
            subout(u, 0, v, 128); halfBytes(u, 128);
            addin(r, s, 128); doubleBytes(s, 128);
        }
        else
        {
            subout(v, 0, u, 128); halfBytes(v, 128);
            addin(s, r, 128); doubleBytes(r, 128);
        }
        k++;
    }
    if (1 != u[0]) { printf("not relatively prime!"); return; }
    if (bytecmp(a->val, r, 128) < 1) { subout(r, 0, a->val, 128); }

    for (i = 1;i <= k - n; i++)
    {
        if ((r[0] & 0x01) ^ 0x01)
        {
            halfBytes(r, 128);
        }
        else
        {
            addin(r, a->val, 128); halfBytes(r, 128);
        }
    }
    subout(rr->val, 0, r, 128);
}

//模逆，phi是奇数采用Montgomery模逆，偶数则采用扩展的欧几里德算法
void modInv(u1kbit *r, u1kbit * e, u1kbit *phi)                    //r = (e^-1) mod phi
{
    if (phi->val[0] & 0x01)            //phi是奇数采用Montgomery模逆
    {
        u1kbit rr;
        memset(&rr, 0, sizeof(u1kbit));

        monInverse(&rr, e, phi);
        memset(r, 0, sizeof(u1kbit));
        r->val[0] = 0x00000001;
        monPro_FIOS(r->val, rr.val, r->val, phi->val, 128);
    }
    else                            //phi是偶数则采用扩充的欧几里德算法求逆
    {
        exGcd(r, e, phi);
    }
}

//模幂运算，采用Montgomery模乘实现
void monExp(u1kbit *r, u1kbit *a, u1kbit *e, u1kbit *n)            //r = a^e mod n
{
    u1kdiv x;
    u2kbit xx;
    int m = 0, t = 0;
    u1byte *p = NULL;

    p = (u1byte *)(e->val);
    e->len = m = getRelLen(e->val, 128);
    t = p[m - 1];
    m = m * 8;
    while ((!(t & 0x0080)) && (t = t << 1) && (--m));

    memset(&xx, 0, sizeof(u2kbit)); memset(&x, 0, sizeof(u1kbit));
    xx.val[32] = 0x01;

    transResidue(r, a, n);
    bigIntDiv(&x, &xx, n);

    for (t = m - 1; t >= 0; t--)
    {
        monPro_FIOS(&x.rem.val, &x.rem.val, &x.rem.val, n->val, 128);
        if (p[t >> 3] & (0x01 << (t & 0x07)))
        {
            monPro_FIOS(&x.rem.val, &x.rem.val, r->val, n->val, 128);
        }
    }
    memset(r, 0, sizeof(u1kbit));
    r->val[0] = 0x00000001;
    monPro_FIOS(r->val, &x.rem.val, r->val, n->val, 128);
}

//辅助函数，将字符串str表示的16进制数存入1kbit的a中，注意最大1024位，即str最长256
void strToUbit(u1kbit *a, char * str)
{
    int i = 0, len = strlen(str);
    char temp[9];
    for (i = 0; i<32; i++)
    {
        if (len > 0) {
            len = len - 8;
            if (len > 0) {
                memcpy(temp, str + len, 8);
                temp[8] = '\0';
            }
            else {
                memcpy(temp, str, 8 + len);
                temp[8 + len] = '\0';
            }
            sscanf(temp, "%x", &(a->val[i]));
        }
        else {
            a->val[i] = 0;
        }
    }
}

//辅助函数，将1k或2k数据格式化或非格式化输出，模式由op控制
void prtBigInt(void *a, int op)
{
    int i = 0, k = 0;
    switch (op)
    {
    case U1K_FMT:
        i = 31;
        while ((0 == ((u1kbit *)a)->val[i]) && (--i) >= 0);
        for (; i >= 0; i--)
        {
            printf("%08x ", ((u1kbit *)a)->val[i]);
            k++;
            if (0 == (k & 0x07)) {
                printf("\n     ");
            }
        }
        printf("\n");
        break;
    case U1K_NOE:
        i = 31;
        while ((0 == ((u1kbit *)a)->val[i]) && (--i) >= 0);
        for (; i >= 0; i--)
        {
            printf("%08x", ((u1kbit *)a)->val[i]);
        }
        break;
    case U2K_FMT:
        i = 63;
        while ((0 == ((u1kbit *)a)->val[i]) && (--i) >= 0);
        for (; i >= 0; i--)
        {
            printf("%08x ", ((u2kbit *)a)->val[i]);
            k++;
            if (0 == (k & 0x07)) {
                printf("\n     ");
            }
        }
        printf("\n");
        break;
    case U2K_NOE:
        i = 63;
        while ((0 == ((u1kbit *)a)->val[i]) && (--i) >= 0);
        for (; i >= 0; i--)
        {
            printf("%08x", ((u2kbit *)a)->val[i]);
        }
        break;
    default:printf("op error!");
    }
}

int main(void)
{
    u1kbit p, q, N, phi, m, m1, c, d, e;
    u1kbit tp, tq;
    u2kbit tt; u1kdiv dd;
    time_t t1, t2;

    memset(&p, 0, sizeof(u1kbit)); memset(&q, 0, sizeof(u1kbit));
    memset(&tp, 0, sizeof(u1kbit)); memset(&tq, 0, sizeof(u1kbit));
    memset(&N, 0, sizeof(u1kbit)); memset(&phi, 0, sizeof(u1kbit));
    memset(&m, 0, sizeof(u1kbit)); memset(&m1, 0, sizeof(u1kbit));
    memset(&c, 0, sizeof(u1kbit)); memset(&d, 0, sizeof(u1kbit)); 
    memset(&e, 0, sizeof(u1kbit));
    memset(&tt, 0, sizeof(u2kbit)); memset(&dd, 0, sizeof(u1kdiv));

    strToUbit(&p, "DB02DC8229318E9A188BB5772022943A1B3A261B5B2142F1AC9ACE199652308733E"
        "588BA33A4F4DD56811837E3D18D1DE2ED124C16B8115BEA88A1A51AEA1BBF");
    strToUbit(&q, "EA1234DE027A1E374B41EA67F133743AAB3E721AB087525CD59377A5E9A19300428"
        "528DBAFCA12B2FB5B8D0441E9C70EF28B8D251686F49A3769745706C53DD5");
    strToUbit(&e, "10001");
    strToUbit(&m, "EAE349B819996957AD14CD987486FF48548511703B036C903E8C8A1FC6EB25A970B"
        "11BE2D6553AAED8BF46D4806D8A8F24A68F8E320B20CD55138387");

    printf("p =\n"); prtBigInt(&p, U1K_NOE); printf("\n");
    printf("q =\n"); prtBigInt(&q, U1K_NOE); printf("\n");

    //生成N
    t1 = clock();
    mul(&tt, &p, &q); memcpy(N.val, tt.val, 128);
    t2 = clock();
    printf("N = p*q\n"); prtBigInt(&N, U1K_NOE); printf("\n");
    printf("耗时：%dms\n", t2 - t1);

    //计算phi
    memcpy(tp.val, p.val, 128); memcpy(tq.val, q.val, 128);
    wordSubout(tp.val, 0x01); wordSubout(tq.val, 0x01);
    t1 = clock();
    mul(&tt, &tp, &tq); memcpy(phi.val, tt.val, 128);
    t2 = clock();
    printf("phi = (p-1)*(q-1)\n"); prtBigInt(&phi, U1K_NOE); printf("\n");
    printf("耗时：%dms\n", t2 - t1);

    printf("e =\n"); prtBigInt(&e, U1K_NOE); printf("\n");

    //密钥对生成
    t1 = clock();
    modInv(&d, &e, &phi);
    t2 = clock();
    printf("d = e^-1 mod phi\n"); prtBigInt(&d, U1K_NOE); printf("\n");
    printf("耗时：%dms\n", t2 - t1);

    //加密
    printf("m =\n"); prtBigInt(&m, U1K_NOE); printf("\n");
    t1 = clock();
    monExp(&c, &m, &e, &N);
    t2 = clock();
    printf("c = m^e mod N\n"); prtBigInt(&c, U1K_NOE); printf("\n");
    printf("耗时：%dms\n", t2 - t1);
    
    //解密
    t1 = clock();
    monExp(&m1, &c, &d, &N);
    t2 = clock();

    printf("m1 = c^d mod N\n"); prtBigInt(&m1, U1K_NOE); printf("\n");
    printf("耗时：%dms\n", t2 - t1);

    //system("pause");
    return 0;
}
