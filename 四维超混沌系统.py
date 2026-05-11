import numpy as np
import matplotlib.pyplot as plt
from scipy.integrate import odeint
from mpl_toolkits.mplot3d import Axes3D

plt.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'KaiTi', 'FangSong']
plt.rcParams['axes.unicode_minus'] = False

# 1. 定义方程
def my_system(state, t, a, b, c, d_param, r):
    x, y, z, w = state
    dxdt = a * (y - x) + w
    dydt = d_param * x - x * z + c * y
    dzdt = x * y - b * z
    dwdt = x * z + r * w
    return [dxdt, dydt, dzdt, dwdt]

# 2. 参数 (保持你要求的数值)
a, b, c, r = 35, 3, 12, 0.5
d_param = 7
params = (a, b, c, d_param, r)

# 3. 求解 (关键修改：将时间从 20 增加到 100，让线条变密)
# 初始状态（与HyperchaoticChenUtil.defaultConfig一致）
initial_state = [0.1179, 0.2318, 0.3361, 0.4517]
t = np.arange(0, 100, 0.01)  # 时间延长，轨迹会更长更密

print("正在计算...")
solution = odeint(my_system, initial_state, t, args=params)

x = solution[:, 0]
y = solution[:, 1]
z = solution[:, 2]
w = solution[:, 3]

# 4. 绘图
fig = plt.figure(figsize=(16, 12))

# --- 子图 1: x-y-z ---
ax1 = fig.add_subplot(221, projection='3d')
ax1.plot(x, y, z, lw=0.5, color='blue') # lw=0.5 让线条细一点，更像论文图
ax1.set_xlabel('X Axis')
ax1.set_ylabel('Y Axis')
ax1.set_zlabel('Z Axis')
ax1.set_title('(a) X-Y-Z Projection')

# --- 子图 2: x-z-w ---
ax2 = fig.add_subplot(222, projection='3d')
ax2.plot(x, z, w, lw=0.5, color='blue')
ax2.set_xlabel('X Axis')
ax2.set_ylabel('Z Axis')
ax2.set_zlabel('W Axis')
ax2.set_title('(b) X-Z-W Projection')

# --- 子图 3: y-z-w ---
ax3 = fig.add_subplot(223, projection='3d')
ax3.plot(y, z, w, lw=0.5, color='blue')
ax3.set_xlabel('Y Axis')
ax3.set_ylabel('Z Axis')
ax3.set_zlabel('W Axis')
ax3.set_title('(c) Y-Z-W Projection')

# --- 子图 4: x-y-w ---
ax4 = fig.add_subplot(224, projection='3d')
ax4.plot(x, y, w, lw=0.5, color='blue')
ax4.set_xlabel('X Axis')
ax4.set_ylabel('Y Axis')
ax4.set_zlabel('W Axis')
ax4.set_title('(d) X-Y-W Projection')

plt.tight_layout()
plt.show()