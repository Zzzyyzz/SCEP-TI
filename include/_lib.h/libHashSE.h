/**
MIT License

Copyright (c) 2021 hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
 * @file libHashSE.h (https://www.seu.edu.cn/)
 * @author hwu(hwu@seu.edu.cn), caymanhu(caymanhu@qq.com)
 * @brief (single counter, multi counter) (sketch，BF) library, (单计数器，多计数器)的(sketch，BF)库 -- 底层使用farmhash
 * @version 0.1
 * @date 2021-09-03
 */

#ifndef LIB_HASH_SE_H
#define LIB_HASH_SE_H

#include <cstdlib>
#include <cstring>
#include <stdint.h>
#include <string>

/**
 * @brief 单计数器(skech or BF)接口
 * hash表个数为4
 */
class ISketchCount
{
public:
    /**
     * @brief Destroy
     */
    virtual ~ISketchCount(){}
public:
    /**
     * @brief 数据清空
     */
    virtual void clear() = 0;

    /**
     * @brief Get the Hash Pos object
     * get第k个hash值
     * @param k 
     * @return uint32_t hash值
     */
    virtual uint32_t getHashPos(int k) = 0;

    /**
     * @brief 根据数据计算所有hash值
     * 
     * @param element 数据存放内存指针
     * @param length 数据长度
     * @return true 成功
     * @return false 失败
     */
    virtual bool calHashKey(const uint8_t *element, unsigned length) = 0;

    /**
     * @brief 根据数据计算所有hash值
     * 
     * @param element 数据存放内存指针
     * @param length 数据长度
     * @return true 成功
     * @return false 失败
     */
    virtual bool calHashKeyB(const uint8_t *element, unsigned length) = 0;
public:
    /**
     * @brief check buffer
     * 
     * @return true 
     * @return false 
     */
    virtual bool checkBuf() = 0;

    /**
     * @brief Get the Key Value object
     * 
     * @return int 需要hash值个数
     */
    virtual int getKeyValue() = 0;

    /**
     * @brief Get the Unit Size object
     * 
     * @return int 单元计数器大小，uint8_t 1, uint16_t 2, uint32_t 4
     */
    virtual int getUnitSize() = 0;

    /**
     * @brief Get the Array Len object
     * 
     * @return int 一个hash表的长度
     */
    virtual int getArrayLen() = 0;
public:             //功能方法
    /**
     * @brief Get the Min object
     * 获得最小值（不做累加）
     * @return uint32_t 最小值
     */
    virtual uint32_t getMin() = 0;

    /**
     * @brief 累加后得到最小值
     * 
     * @return uint32_t 最小值
     */
    virtual uint32_t countMin() = 0;

    /**
     * @brief 加值后得到最小值
     * 
     * @return uint32_t 最小值
     */
    virtual uint32_t addv_countMin(uint32_t v) = 0;

    /**
     * @brief 累加到阈值（最大值），然后得到最小值
     * 
     * @param thre 阈值
     * @return uint32_t 最小值 
     */
    virtual uint32_t countMinThreshold(uint32_t thre) = 0;

    /**
     * @brief 累加到阈值（最大值），得到最大值，然后减去最大值
     * 
     * @param thre 阈值
     * @return true 完成减的动作
     * @return false 
     */
    virtual bool count2Cut(uint32_t thre) = 0;
    
    virtual int getOverflow() = 0;
public:
    /**
     * @brief 得到bit位计数器值，位如果为1，需要所有计数器的位都为1
     * 
     * @return uint8_t bit位计数器值
     */
    virtual uint8_t getUCBits() = 0;

    /**
     * @brief 设置 bit位计数器值，按位或
     * 
     * @param bits uint8_t
     * @return true 
     * @return false 
     */
    virtual bool setUCBits(uint8_t bits) = 0;

    /**
     * @brief 得到bit位计数器值，位如果为1，需要所有计数器的位都为1
     * 
     * @return uint16_t 
     */
    virtual uint16_t getUSBits() = 0;

    /**
     * @brief 设置 bit位计数器值，按位或
     * 
     * @param bits uint16_t
     * @return true 
     * @return false 
     */
    virtual bool setUSBits(uint16_t bits) = 0;

    /**
     * @brief 得到bit位计数器值，位如果为1，需要所有计数器的位都为1
     * 
     * @return uint32_t 
     */
    virtual uint32_t getULBits() = 0;

    /**
     * @brief 设置 bit位计数器值，按位或
     * 
     * @param bits uint32_t
     * @return true 
     * @return false 
     */
    virtual bool setULBits(uint32_t bits) = 0;
};

/**
 * @brief 多单计数器(skech or BF)接口
 * hash表个数为4
 */
class ISketchMulCount
{
public:
    /**
     * @brief Destroy
     */
    virtual ~ISketchMulCount(){}
public:
    /**
     * @brief 数据清空，重复使用
     */
    virtual void clear() = 0;

    /**
     * @brief Get the Hash Pos of k
     * 
     * @param k 第k个hash值
     * @return uint32_t hash值
     */
    virtual uint32_t getHashPos(int k) = 0;

    /**
     * @brief 通过数据计算所有hash值
     * 
     * @param element 数据指针
     * @param length 数据长度
     * @return true 成功
     * @return false 失败
     */
    virtual bool calHashKey(const uint8_t *element, unsigned length) = 0;

    /**
     * @brief 通过数据计算所有hash值
     * 
     * @param element 数据指针
     * @param length 数据长度
     * @return true 成功
     * @return false 失败
     */
    virtual bool calHashKeyB(const uint8_t *element, unsigned length) = 0;
public:
    /**
     * @brief check buffer
     * 
     * @return true 
     * @return false 
     */
    virtual bool checkBuf() = 0;

    /**
     * @brief Get hash个数
     * 
     * @return int 
     */
    virtual int getKeyValue() = 0;

    /**
     * @brief Get 单元多计数器大小
     * 
     * @return int 
     */
    virtual int getUnitSize() = 0;

    /**
     * @brief Get 每个hash表中单元个数
     * 
     * @return int 
     */
    virtual int getArrayLen() = 0;
public:
    /**
     * @brief 多位置hash后，取得多位置多计数器的数据
     * 
     * @param data 数据指针，4个计数器（unit_size*4）依次排放
     * @return true 
     * @return false 
     */
    virtual bool getData(unsigned char* data) = 0;

    /**
     * @brief 把多个计数器数据会写到主数据中
     * 
     * @param data  数据指针，4个计数器（unit_size*4）依次排放
     * @return true 
     * @return false 
     */
    virtual bool setData(unsigned char* data) = 0;  
public:
    /**
     * @brief Get the Buffer object 测试使用，不开放
     * 
     */
    virtual uint8_t* getBuffer(int index) = 0;
};

/**
 * @brief hash 工具
 * 
 */
class CHashTools
{
public:
    /**
     * @brief 通过bit位求得所需单元数，2^n
     * 
     * @param n 
     * @return uint32_t 
     */
    static uint32_t two_to_power_of(int n);

    /**
     * @brief 计算“数据”的hash值
     * 
     * @param element 数据指针
     * @param length 长度
     * @param bit_num bit位
     * @return uint32_t 返回hash值
     */
    static uint32_t HashBuffer(const uint8_t*element, uint32_t length, uint32_t bit_num);
    static uint32_t HashBuffer_kernel(const uint8_t*element, uint32_t length, uint32_t bit_num);

    /**
     * @brief 单计数器的(sketch, hash)生成函数
     * 
     * @param bit_num 单元个数的bit
     * @param unit_size 单元大小
     * @param type 0--sketch, 1--BF
     * @return ISketchCount* 返回multi_addr_count接口指针
     */
    static ISketchCount* create_SKC(int bit_num, int unit_size, int type=0);

    /**
     * @brief 多计数器的(sketch, hash)生成函数
     * 
     * @param bit_num 单元个数的bit
     * @param unit_size 单元大小
     * @param type 0--sketch, 1--BF
     * @return ISketchMulCount* 返回multi_addr_multi_count接口指针
     */
    static ISketchMulCount* create_SKMC(int bit_num, int unit_size, int type=0);

    /**
     * @brief 自定义多计数器的(sketch, hash)生成函数
     * 
     * @param num_hash hash个数
     * @param bit_num 单元个数的bit
     * @param unit_size 单元大小
     * @return ISketchMulCount* 返回multi_addr_multi_count接口指针
     */
    static ISketchMulCount* create_user_SKMC(int num_hash, int bit_num, int unit_size);
};

#endif