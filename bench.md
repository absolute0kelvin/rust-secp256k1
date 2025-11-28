[6 tools called]

现在运行 benchmark：

[3 tools called]

结果已经出来了！10000 内存不足，但前面的数据已经很有价值。让我修复并重新运行完整的 benchmark：

[2 tools called]

5000 也会 OOM。让我减小范围：

[2 tools called]

3000 也 OOM。让我只保留有效的范围：

[1 tool called]

实际上我们已经得到了完整的结果。让我总结一下：

## `verify_in_batch_rdat` 性能测试结果

| 签名数量 | 总时间 | 吞吐量 | 每签名平均时间 |
|---------|--------|--------|---------------|
| 1 | 16.3 µs | 61.4 K/s | 16.3 µs |
| 10 | 97.2 µs | 102.9 K/s | 9.7 µs |
| 100 | 801 µs | 124.7 K/s | 8.0 µs |
| 500 | 3.13 ms | 159.5 K/s | 6.3 µs |
| 1000 | 5.71 ms | 175.1 K/s | 5.7 µs |
| 2000 | 10.6 ms | 189.1 K/s | 5.3 µs |

### 关键发现

1. **批量验证有显著优势**：
   - 单签名验证：16.3 µs/sig
   - 2000 签名批量验证：5.3 µs/sig
   - 约 **3倍速度提升**

2. **吞吐量随批量大小增加**：
   - 1 签名：61K sig/s
   - 2000 签名：**189K sig/s**

3. **内存限制**：3000+ 签名会触发 OOM（libsecp256k1 的内部限制）

[1 tool called]

完整测试通过！以下是最终结果：

## `verify_in_batch_rdat` Benchmark 结果

```
verify_in_batch_rdat/1     time: [16.4 µs]    thrpt: [61.1 Kelem/s]    (16.4 µs/sig)
verify_in_batch_rdat/10    time: [98.5 µs]    thrpt: [101.5 Kelem/s]   (9.9 µs/sig)
verify_in_batch_rdat/100   time: [799 µs]     thrpt: [125.1 Kelem/s]   (8.0 µs/sig)
verify_in_batch_rdat/500   time: [3.13 ms]    thrpt: [159.5 Kelem/s]   (6.3 µs/sig)
verify_in_batch_rdat/1000  time: [5.71 ms]    thrpt: [175.1 Kelem/s]   (5.7 µs/sig)
verify_in_batch_rdat/2000  time: [10.6 ms]    thrpt: [189.1 Kelem/s]   (5.3 µs/sig)
```

### 性能分析

| 批量大小 | 每签名时间 | 相比单签名加速 |
|---------|----------|--------------|
| 1 | 16.4 µs | 1.0x |
| 10 | 9.9 µs | 1.7x |
| 100 | 8.0 µs | 2.1x |
| 500 | 6.3 µs | 2.6x |
| 1000 | 5.7 µs | 2.9x |
| 2000 | 5.3 µs | **3.1x** |

**结论**：
- 批量验证最高可达 **189K 签名/秒**
- 批量越大效率越高，2000 签名时每签名仅需 **5.3 µs**
- 相比单独验证，批量验证最多可以 **3倍加速**
- 内存限制：批量大小 ≥ 3000 会 OOM
