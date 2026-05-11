import numpy as np
import matplotlib.pyplot as plt
from scipy.integrate import odeint

# 1. 定义四维系统
def my_system(state, t, a, b, c, d_param, r):
    x, y, z, w = state
    dxdt = a * (y - x) + w
    dydt = d_param * x - x * z + c * y
    dzdt = x * y - b * z
    dwdt = x * z + r * w
    return [dxdt, dydt, dzdt, dwdt]

# 2. 设置参数
a, b, c, r = 35, 3, 12, 0.5
d_param = 7
params = (a, b, c, d_param, r)

# 3. 求解微分方程
# 初始状态（与HyperchaoticChenUtil.defaultConfig一致）
initial_state = [0.1179, 0.2318, 0.3361, 0.4517]
t = np.arange(0, 100, 0.01)  # 延长计算时间以获得更密集的轨迹

print("正在计算轨迹...")
solution = odeint(my_system, initial_state, t, args=params)

# 提取四个变量
x = solution[:, 0]
y = solution[:, 1]
z = solution[:, 2]
w = solution[:, 3]

# 4. 绘制所有二维组合相图
plt.figure(figsize=(15, 12))

# --- 子图 1: x-y 平面 ---
plt.subplot(231)
plt.plot(x, y, lw=0.5, color='blue')
plt.xlabel('X Axis', fontsize=10)
plt.ylabel('Y Axis', fontsize=10)
plt.title('(a) X-Y Plane', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)

# --- 子图 2: x-z 平面 ---
plt.subplot(232)
plt.plot(x, z, lw=0.5, color='blue')
plt.xlabel('X Axis', fontsize=10)
plt.ylabel('Z Axis', fontsize=10)
plt.title('(b) X-Z Plane', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)

# --- 子图 3: x-w 平面 ---
plt.subplot(233)
plt.plot(x, w, lw=0.5, color='blue')
plt.xlabel('X Axis', fontsize=10)
plt.ylabel('W Axis', fontsize=10)
plt.title('(c) X-W Plane', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)

# --- 子图 4: y-z 平面 ---
plt.subplot(234)
plt.plot(y, z, lw=0.5, color='blue')
plt.xlabel('Y Axis', fontsize=10)
plt.ylabel('Z Axis', fontsize=10)
plt.title('(d) Y-Z Plane', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)

# --- 子图 5: y-w 平面 ---
plt.subplot(235)
plt.plot(y, w, lw=0.5, color='blue')
plt.xlabel('Y Axis', fontsize=10)
plt.ylabel('W Axis', fontsize=10)
plt.title('(e) Y-W Plane', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)

# --- 子图 6: z-w 平面 ---
plt.subplot(236)
plt.plot(z, w, lw=0.5, color='blue')
plt.xlabel('Z Axis', fontsize=10)
plt.ylabel('W Axis', fontsize=10)
plt.title('(f) Z-W Plane', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)

plt.tight_layout()
plt.show()