import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

df = pd.read_csv('2_1_01_jpg_histogram.csv')
gray_levels = df['GrayLevel']
original = df['OriginalCount']
encrypted = df['EncryptedCount']

plt.rcParams['font.sans-serif'] = ['SimHei'] 
plt.rcParams['axes.unicode_minus'] = False

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

# 原始图像直方图
ax1.bar(gray_levels, original, width=1.0, color='gray', edgecolor='none')
ax1.set_title('(a) 原始图像灰度直方图')
ax1.set_xlabel('灰度级')
ax1.set_ylabel('像素频数')
ax1.set_xlim(0, 255)

# 加密图像直方图
ax2.bar(gray_levels, encrypted, width=1.0, color='gray', edgecolor='none')
ax2.set_title('(b) 选择性加密图像灰度直方图')
ax2.set_xlabel('灰度级')
ax2.set_ylabel('像素频数')
ax2.set_xlim(0, 255)

plt.tight_layout()
plt.savefig('histogram_comparison.png', dpi=300, bbox_inches='tight')
plt.show()