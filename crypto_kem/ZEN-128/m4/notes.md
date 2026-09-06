## 1. FastInversion
This algorithm computes the inverse of a binary polynomial `f` modulo

```text
<x^n + 1, 2>  =  F_2[x] / (x^n + 1)
```

assuming `n = 2^l`. In other words, it tries to find `f_inv` such that

```text
f * f_inv ≡ 1 mod (x^n + 1, 2).
```

If no inverse exists, it outputs `⊥`.

**Why the first test matters**

Over `F_2`, when `n = 2^l`,

```text
x^n + 1 = x^{2^l} + 1 = (x + 1)^{2^l}.
```

So the ring is essentially modulo a power of `x + 1`. A polynomial is invertible modulo `(x + 1)^n` iff it is not divisible by `x + 1`.

Reducing modulo `<x + 1, 2>` means setting `x = 1` over `F_2`. So:

```text
f ≡ 0 mod <x + 1, 2>
```

means `f` is divisible by `x + 1`, hence not invertible. Therefore outputting `⊥` is correct.

If `f` is not zero modulo `<x + 1, 2>`, then since the field is `F_2`, we have:

```text
f ≡ 1 mod x + 1.
```

So the initial inverse modulo `x + 1` is simply:

```text
f_inv = 1.
```

**Core invariant**

Let

```text
m_i = x^{2^i} + 1.
```

The algorithm maintains:

```text
f * f_inv = 1 + m_i * k        mod (x^n + 1, 2).
```

At the start, `i = 0`, so `m_0 = x + 1`.

The algorithm sets:

```text
k = (f + 1) / (x + 1),
f_inv = 1.
```

Because over `F_2`:

```text
f = 1 + (x + 1)k.
```

So the invariant holds initially.

**What one loop iteration does**

At step `i`, assume:

```text
f * f_inv = 1 + m_i k.
```

The goal is to improve the inverse so that the error is divisible by the next modulus:

```text
m_{i+1} = x^{2^{i+1}} + 1.
```

In characteristic 2:

```text
m_{i+1} = x^{2^{i+1}} + 1 = (x^{2^i} + 1)^2 = m_i^2.
```

So each iteration doubles the precision: from modulo `m_i` to modulo `m_i^2`.

The algorithm chooses:

```text
b = k f_inv mod m_i.
```

Then updates:

```text
f_inv' = f_inv + m_i b.
```

Now compute:

```text
f f_inv'
= f(f_inv + m_i b)
= f f_inv + m_i f b
= 1 + m_i k + m_i f b
= 1 + m_i(k + f b).
```

Because `f_inv` is already an inverse of `f` modulo `m_i`, we have:

```text
f f_inv ≡ 1 mod m_i,
```

so:

```text
f b = f(k f_inv) ≡ k mod m_i.
```

Therefore:

```text
k + f b ≡ k + k ≡ 0 mod m_i
```

since arithmetic is over `F_2`.

So `k + f b` is divisible by `m_i`, meaning:

```text
k + f b = m_i k'
```

for some new `k'`. Hence:

```text
f f_inv' = 1 + m_i^2 k' = 1 + m_{i+1} k'.
```

That proves the invariant advances from `i` to `i + 1`.

**Why the final output is correct**

After `l = log2(n)` iterations:

```text
m_l = x^{2^l} + 1 = x^n + 1.
```

The invariant gives:

```text
f * f_inv = 1 + (x^n + 1)k.
```

Therefore:

```text
f * f_inv ≡ 1 mod (x^n + 1, 2).
```

So `f_inv` is the inverse of `f` in the binary quotient ring.

In short: this is a fast Hensel/Newton-style inversion algorithm. It starts with the trivial inverse modulo `x + 1`, then repeatedly doubles the precision until it has an inverse modulo `x^n + 1`.

## 2. Optimizing FastInversion with different bit representation
结论：`FastInversion` 的输入 `f` 在调用点确实是 `0/1` 二进制多项式；把 128 个系数压成 `uint32_t f[4]` 是合理的，并且很可能能明显加速 `FastInversion`，尤其是当前最重的二进制多项式乘法部分。

**1. f 的范围**

原始 `poly_generate_f()` 生成的 512 项 `f` 不是 `0/1`，而是 CBD-1：

```c
r[16*i+j] = a - b;
```

所以原始系数范围是：

```text
{-1, 0, 1}
```

但传给 `FastInversion(f2, t0)` 的不是原始 `f`，而是 keygen 中的 `t0`：

```c
t0[i] = (f[i] & 1)
      ^ (f[i + 128] & 1)
      ^ (f[i + 256] & 1)
      ^ (f[i + 384] & 1);
```

见 [pke.c](/home/hjh/Documents/project/ngccm4/crypto_kem/ZEN_128/ref/pke.c:26)。

因此：

```text
t0[i] ∈ {0, 1}
```

m4 版本里 `poly_xor4()` 也是同样逻辑，并且最后 `and` 掩码 `0x00010001`，所以输出仍然是半字形式的 `0/1`。

另外：

```c
if(check_poly_inv_Z2(t0)) continue;
```

保证 `t0(1) = 1`，也就是它在 `F2[x]/(x^128+1)` 中可逆。

**2. packed 表示是否正确**

可以定义：

```c
typedef uint32_t poly2_128[4];
```

其中：

```text
bit i = coefficient of x^i
```

也就是：

```text
f[0] 的 bit 0..31   -> coeff 0..31
f[1] 的 bit 0..31   -> coeff 32..63
f[2] 的 bit 0..31   -> coeff 64..95
f[3] 的 bit 0..31   -> coeff 96..127
```

这种表示和算法完全匹配，因为 `F2` 里：

```text
加法 = XOR
乘法选择 = mask AND
x 乘法 = cyclic bit rotation
mod x^n+1 = fold by XOR
```

我做了一个临时 packed 原型，随机测试 10000 个满足 `f(1)=1` 的二进制输入，packed 版本输出和当前 `int16_t[128]` 版本一致。这个验证了表示方式和算法步骤是等价的。

**3. 为什么可能加速**

当前 `FastInversion` 里最重的是：

```c
mulf_in_R2_N4(b, tmp_f, tmp);
```

它每轮做大约：

```text
128 * 128 = 16384
```

次系数级 masked XOR。

主循环有 6 轮，所以这个部分约：

```text
6 * 16384 = 98304
```

次半字级操作。

如果改成 `uint32_t[4]`：

```text
128 个系数 = 4 个 32-bit word
```

一次全长 XOR 只需要 4 个 `eor`。乘法也可以变成“按 bit 扫描 multiplier，每次条件 XOR 4 个 word + cyclic rotate”。而且在 FastInversion 第 `n` 轮里，`b` 只有低 `n` 位有效，所以 `b*f mod x^128+1` 不需要扫 128 位，只需要扫：

```text
n = 2,4,8,16,32,64
```

总共才 126 个 multiplier bit。每个 bit 操作 4 个 word，数量级大约是：

```text
126 * 4 = 504
```

个 word 级 masked XOR，加上一些 rotation。相比当前的 98304 个半字级操作，优化空间很大。

在 x86 上如果用 PCLMULQDQ 会更快；在 Cortex-M4 上没有 CLMUL，但 32-bit packed shift-XOR 仍然比 `int16_t[128]` 的双重循环更适合。

**4. 需要修改适配的地方**

最小改法：只优化 keygen 里的 `FastInversion`，decapsulation 先保持原来的展开格式。

需要新增/修改：

```text
poly_xor4_pack()
```

直接从 512 项 `f` 生成 packed `uint32_t[4] t0`，替代当前先生成 `int16_t t0[128]`。

```text
check_poly_inv_Z2_pack()
```

对 4 个 word 求整体 parity：

```c
acc = f[0] ^ f[1] ^ f[2] ^ f[3];
return parity(acc) == 0;
```

返回逻辑保持原函数语义：`1` 表示不可逆。

```text
FastInversion_pack()
```

内部需要 packed 版本的这些操作：

```text
prefix_xor128        // 计算 (f+1)/(x+1)
fold_mod_n           // k mod x^n+1
mul_mod_n_pack       // b = k * f_inv mod x^n+1
mul_by_f_128_pack    // tmp = b * f mod x^128+1
divide_xn_plus1      // k = k / (x^n+1)
finv_update          // f_inv ^= b | (b << n)
```

```text
poly_pack_f2_pack()
```

`f2` 本来最终就是 16 字节。packed `uint32_t[4]` 可以直接存成 16 字节，但要固定 little-endian，不能依赖平台内存布局：

```text
word0 -> bytes 0..3
word1 -> bytes 4..7
word2 -> bytes 8..11
word3 -> bytes 12..15
```

这和当前 `poly_pack_f2()` 的 bit 顺序一致。

**5. 不建议立刻全局替换 `mul_in_R2_n`**

`mul_in_R2_n()` 不只被 `FastInversion` 用，decapsulation 里也用：

```c
mul_in_R2_n(t1, f2, ZEN_N2, mp0);
```

见 [pke.c](/home/hjh/Documents/project/ngccm4/crypto_kem/ZEN_128/m4/pke.c:121)。

所以更稳的路线是：

```text
保留现有 mul_in_R2_n()
新增 packed 专用 helper
只让 FastInversion_pack() 使用 packed helper
```

等 keygen 优化验证通过后，再考虑把 decapsulation 里的 `f2` 也保持 packed，并重写 `mul_in_R2_n(..., n=256)` 和 SimpleDecoding 的旋转 XOR 逻辑。

**6. 常数时间注意点**

packed 版本不能写成：

```c
if ((b >> i) & 1) res ^= rotated_f;
```

因为 bit 是 secret-dependent。应该写成：

```c
mask = 0u - ((b >> i) & 1);
res[w] ^= rotated_f[w] & mask;
```

循环次数只依赖公开的 `n = 2,4,8,16,32,64`，这是可以的。

总体建议：先实现 `FastInversion_pack()` + `poly_xor4_pack()` + `check_poly_inv_Z2_pack()` + `poly_store_f2_pack()`，只改 keygen 路径。这个改动范围小，正确性容易和当前 ref 对拍，性能收益也最集中。

### 2.1 Radix-16 representation
可以用，但要注意：**radix-16 适合做 8x8 bit polynomial 的 base multiplication；不能直接把很多 8x8 乘积用整数加法累加**。在 `F2` 里必须 XOR 累加，而且每个 8x8 乘积后只取每个 nibble 的最低 bit。

我做了一个随机对拍验证：radix-16 cyclic multiplication 对 `n = 8,16,32,64,128` 的结果和当前 `mul_in_R2_n` 的环乘法一致。`n=2,4` 不能直接按 8-bit block ring 处理，建议保留特殊 bit 逻辑。

**Radix-16 表示**

每 8 个二进制系数存入一个 32-bit word：

```text
a0 + a1*x + ... + a7*x^7

=> a0 | a1<<4 | a2<<8 | ... | a7<<28
```

两个这样的 word 做 `UMULL` 得到 64-bit product：

```text
p = A * B
```

因为每个卷积系数最多 8 项，所以不会跨 4-bit lane 进位。然后取：

```text
lo = p_low  & 0x11111111
hi = p_high & 0x11111111
```

`lo` 是低 8 个结果系数，`hi` 是高 7 个结果系数。累加时用：

```c
R[(i+j)   % m] ^= lo;
R[(i+j+1) % m] ^= hi;
```

这里 `m = n / 8`，对应模 `x^n + 1` 的环折叠。

**对当前函数的适配**

当前热点在 [poly.c](/home/hjh/Documents/project/ngccm4/crypto_kem/ZEN_128/ref/poly.c:37)：

```c
mul_in_R2_n(...)
mulf_in_R2_N4(...)
```

它们现在是系数级 masked XOR。radix-16 版本建议新增专用函数，不要直接替换原 API：

```c
void mul_R2_128_rad16(uint32_t r[16],
                      const uint32_t a[16],
                      const uint32_t b[16]);

void mul_R2_n_rad16(uint32_t *r,
                    const uint32_t *a,
                    const uint32_t *b,
                    unsigned n);
```

其中 `mulf_in_R2_N4` 对应 `n=128`，需要 16 个 radix words。`mul_in_R2_n` 在 `FastInversion` 中的 `n=2,4` 建议特殊处理；`n>=8` 可用 radix-16。

**和 dense bit-packed 方法比较**

上一种 `uint32_t[4]` dense bit-packed 方法是：

```text
128 coeffs = 4 words
乘法 = 扫 multiplier bit + masked XOR + cyclic rotate
```

它优点是简单、寄存器少、更新 `k/f_inv` 很自然。缺点是 full 128x128 乘法仍要扫 128 bit，每次要处理 4-word rotate 和 4-word XOR。

radix-16 schoolbook 的 full 128x128 乘法需要：

```text
16 * 16 = 256 次 UMULL
```

每次大约：

```text
UMULL + 2 AND + 2 EOR + 地址更新
```

如果数据已经是 radix-16，通常会比系数级 `int16_t` 快很多；和 dense bit-packed shift/XOR 相比，full multiply 也有竞争力。

**Karatsuba 比较**

以 8-bit radix-16 block 为 base case：

```text
128-bit polynomial = 16 blocks
```

schoolbook：

```text
16^2 = 256 个 8x8 base multiply
```

Karatsuba：

```text
16 blocks -> 3^4 = 81 个 8x8 base multiply
```

所以对于 full `mulf_in_R2_N4`，**radix-16 + Karatsuba 理论上最快**，因为 `UMULL` 数量从 256 降到 81。不过它会增加临时 buffer、XOR 加法和代码复杂度。

对 `FastInversion` 内部更细一点：

```text
b*f, n=2,4,8,16,32,64
```

radix-16 schoolbook 约需要：

```text
16 + 16 + 16 + 32 + 64 + 128 = 272 次 UMULL
```

如果用分治/Karatsuba，约可降到：

```text
~160-200 次 UMULL
```

但小尺寸 `n=2,4,8,16` 上 Karatsuba 开销不一定划算。

**我的判断**

最快路线大概率是混合方案：

```text
n < 16:      用 dense bit-packed / scalar bit logic
n = 16,32:   radix-16 schoolbook 或一层 Karatsuba，需实测
n >= 64:     radix-16 + Karatsuba
full 128:    radix-16 + Karatsuba 最值得
```

如果只想先低风险加速 `FastInversion`，建议先做 **dense `uint32_t[4]` bit-packed**，改动少。

如果目标是进一步优化 `mul_in_R2_n` 和 `mulf_in_R2_N4` 的大乘法，建议做 **radix-16 + Karatsuba**，但要让 `f/k/b/tmp/f_inv` 全程保持 radix-16，避免每次 pack/unpack 吃掉收益。

常数时间上，两种方法都可以安全实现：循环次数只依赖公开的 `n`，选择 bit 时用 mask，不用 secret-dependent branch。


## 3. SimpleDecoding的优化思路
可以加速，重点就在 [pke.c 的 SimpleDecoding](/home/hjh/Documents/project/ngccm4/crypto_kem/ZEN_128/m4/pke.c:134) 这段，尤其是 [164-167 行](/home/hjh/Documents/project/ngccm4/crypto_kem/ZEN_128/m4/pke.c:164) 的 `128 * 256` 半字循环。

**算法到 C 的对应**
`a` 在实现里是 `poly_cp(t0, t1)` 后的 `t0`。  
`δ <- a mod <2, x^(n/4)+1>` 对应：

```c
poly_xor4(t1, t0);
```

`m' = a f_inv mod <2, x^(n/2)+1>` 已经被优化为 radix16/汇编：

```c
r2_radix16_pack(t1_rad, t1, ZEN_N2);
r2_radix16_mul_256_asm(mp0_rad, t1_rad, f2_rad);
```

真正还没优化干净的是 Step 3-5：根据 `δ` 找单项式位置、比较四个 `v_j = q/2 - |a*|`，然后把 `f_inv` 循环移位后异或进消息。

**最主要的加速点**
当前 C 没有先找出 `δ` 的单项式位置，而是对 `i = 0..127` 全部扫一遍，并且每个 `i` 都做 256 次：

```c
t2[j] ^= selected_shifted_f2[j];
```

也就是约 `32768` 次 halfword 级 load/xor/store。这个可以降很多。

如果严格按 Algorithm 3 实现，应该先常数时间扫描 `δ`：

```c
idx = index of the unique 1 in δ
valid = (weight(δ) == 1)
```

然后只对这个 `idx` 计算四个候选：

```c
v0 = q/2 - abs(t0[idx])
v1 = q/2 - abs(t0[idx + N/4])
v2 = q/2 - abs(t0[idx + N/2])
v3 = q/2 - abs(t0[idx + 3N/4])
```

再选 `j*`，最后只做一次：

```c
t2 = x^(idx + jbit*N/4) * f2
```

这会把核心复杂度从 `128 * 256` 降到一次扫描 `128` 加一次长度 `256` 的循环移位。

**更适合当前代码的 packed 加速**
现在已经有 `f2_rad` 和 `mp0_rad`，但 SimpleDecoding 又在 [135 行](/home/hjh/Documents/project/ngccm4/crypto_kem/ZEN_128/m4/pke.c:135) 把 `f2_rad` 解包成 `int16_t f2`，后面又用 `t2/mp0/mp1` 做 16-bit 操作。这是明显可省的。

建议新增一个内核，例如：

```c
simple_decode_radix16(t2_rad, t0, f2_rad);
```

直接在 radix16 格式中生成 `t2_rad`，然后：

```c
msg_rad[w] = mp0_rad[w] ^ t2_rad[w];  // 只需要前 16 words
r2_radix16_tobytes(m, msg_rad, ZEN_N4);
```

这样可以去掉：

- `r2_radix16_unpack(f2, ...)`
- `r2_radix16_unpack(mp0, ...)`
- `int16_t t2[512]`
- `int16_t mp1[256]`
- `poly_pack_f2(m, mp1)`

同时把内层从 256 个 `int16_t` 操作改成 32 个 `uint32_t` word 操作，甚至按 Algorithm 3 只做一次 packed rotate。

**次级加速点**
`poly_xor4(t1, t0)` 已经是 asm，但可以和 SimpleDecoding 的四系数读取融合，避免单独扫一遍 `t0` 并写 `t1`。

`r2_radix16_pack(t1_rad, t1, 256)` 也可进一步和 `poly_cp/update_cp_asm` 融合：`update_cp_asm` 已经在算 parity，可以直接输出 packed `t1_rad`，省一次 pack。

**安全注意**
不要直接照 DAWN 原始 C 的 `FindOneIdx`/`if` 写法，那是数据相关分支。优化版本应继续用 mask 做 `idx`、`valid`、`j*` 选择。若做 packed rotate，也要注意 `shift` 相关的内存访问模式；在 Cortex-M4 上通常没有数据 cache，但常数时间审计时仍应说明假设。

结论：优先优化 SimpleDecoding 的 [135-175 行](/home/hjh/Documents/project/ngccm4/crypto_kem/ZEN_128/m4/pke.c:135)。最大收益路径是“先常数时间找 δ 单项式，再做一次 radix16 循环移位修正”；保守路径是保持当前语义，把内层 `128*256` 的 halfword XOR 改成 packed word XOR。