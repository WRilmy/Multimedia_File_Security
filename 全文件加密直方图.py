import pandas as pd
import matplotlib.pyplot as plt

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei']  # Windows 常用黑体
# 或者 ['Microsoft YaHei']、['WenQuanYi Zen Hei']（Linux）
plt.rcParams['axes.unicode_minus'] = False   # 解决负号显示异常

df = pd.read_csv('2.1.01.bmp_byte_hist.csv')
x = df['ByteValue']
plain = df['PlainCount']
cipher = df['CipherCount']

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
ax1.bar(x, plain, width=1.0, color='blue', alpha=0.7)
ax1.set_title('明文文件字节分布')
ax1.set_xlabel('字节值 (0-255)')
ax1.set_ylabel('频数')

ax2.bar(x, cipher, width=1.0, color='red', alpha=0.7)
ax2.set_title('全文件加密后密文字节分布')
ax2.set_xlabel('字节值 (0-255)')
ax2.set_ylabel('频数')

plt.tight_layout()
plt.savefig('byte_histogram_full.png', dpi=300)