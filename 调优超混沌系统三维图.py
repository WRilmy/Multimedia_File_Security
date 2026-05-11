import numpy as np
import matplotlib.pyplot as plt
from scipy.integrate import odeint
from mpl_toolkits.mplot3d import Axes3D

plt.rcParams['font.sans-serif'] = ['Microsoft YaHei', 'SimHei', 'KaiTi', 'FangSong']
plt.rcParams['axes.unicode_minus'] = False

# 定义调优版四维超混沌Chen系统
def optimized_system(state, t, a, b, c, d_param, r, e):
    """
    调优版四维超混沌Chen系统
    在第三个方程中添加了e*w项
    
    参数:
    state: 状态向量 [x, y, z, w]
    t: 时间
    a, b, c, d_param, r, e: 系统参数
    """
    x, y, z, w = state
    dxdt = a * (y - x) + w
    dydt = d_param * x - x * z + c * y
    dzdt = x * y - b * z + e * w  # 调优：添加e*w项
    dwdt = x * z + r * w
    return [dxdt, dydt, dzdt, dwdt]

# 主函数：绘制调优系统的三维投影
def plot_optimized_system():
    """绘制调优系统(c=25, d=10, e=3)的三维投影图"""
    
    # 参数设置（与HyperchaoticChenOptimizedUtil.defaultConfig一致）
    a, b, c, d_param, r, e = 35, 3, 25, 10, 0.5, 3
    
    # 时间设置
    t = np.arange(0, 100, 0.001)
    
    # 初始状态（与HyperchaoticChenOptimizedUtil.defaultConfig一致）
    initial_state = [0.1179, 0.2318, 0.3361, 0.4517]
    
    # 计算系统轨迹
    print(f"正在计算调优系统(c={c}, d={d_param}, e={e})的轨迹...")
    params = (a, b, c, d_param, r, e)
    solution = odeint(optimized_system, initial_state, t, args=params)
    
    x, y, z, w = solution[:, 0], solution[:, 1], solution[:, 2], solution[:, 3]
    
    # 创建图表
    fig = plt.figure(figsize=(16, 12))
    
    # --- 子图1: x-y-z投影 ---
    ax1 = fig.add_subplot(221, projection='3d')
    ax1.plot(x, y, z, lw=0.5, color='blue')
    ax1.set_xlabel('X Axis')
    ax1.set_ylabel('Y Axis')
    ax1.set_zlabel('Z Axis')
    ax1.set_title('(a) 调优系统 X-Y-Z 投影 (c=25, d=10, e=3)')
    
    # --- 子图2: x-z-w投影 ---
    ax2 = fig.add_subplot(222, projection='3d')
    ax2.plot(x, z, w, lw=0.5, color='blue')
    ax2.set_xlabel('X Axis')
    ax2.set_ylabel('Z Axis')
    ax2.set_zlabel('W Axis')
    ax2.set_title('(b) 调优系统 X-Z-W 投影 (c=25, d=10, e=3)')
    
    # --- 子图3: y-z-w投影 ---
    ax3 = fig.add_subplot(223, projection='3d')
    ax3.plot(y, z, w, lw=0.5, color='blue')
    ax3.set_xlabel('Y Axis')
    ax3.set_ylabel('Z Axis')
    ax3.set_zlabel('W Axis')
    ax3.set_title('(c) 调优系统 Y-Z-W 投影 (c=25, d=10, e=3)')
    
    # --- 子图4: x-y-w投影 ---
    ax4 = fig.add_subplot(224, projection='3d')
    ax4.plot(x, y, w, lw=0.5, color='blue')
    ax4.set_xlabel('X Axis')
    ax4.set_ylabel('Y Axis')
    ax4.set_zlabel('W Axis')
    ax4.set_title('(d) 调优系统 X-Y-W 投影 (c=25, d=10, e=3)')
    
    plt.suptitle('调优版四维超混沌Chen系统三维投影 (c=25, d=10, e=3)', fontsize=16, y=1.02)
    plt.tight_layout()
    plt.show()
    
    # 显示统计信息
    print("\n" + "="*60)
    print("调优系统(c=25, d=10, e=3)轨迹统计信息")
    print("="*60)
    print(f"  x范围: [{x.min():.4f}, {x.max():.4f}], 均值: {x.mean():.4f}, 标准差: {x.std():.4f}")
    print(f"  y范围: [{y.min():.4f}, {y.max():.4f}], 均值: {y.mean():.4f}, 标准差: {y.std():.4f}")
    print(f"  z范围: [{z.min():.4f}, {z.max():.4f}], 均值: {z.mean():.4f}, 标准差: {z.std():.4f}")
    print(f"  w范围: [{w.min():.4f}, {w.max():.4f}], 均值: {w.mean():.4f}, 标准差: {w.std():.4f}")

# 运行主函数
if __name__ == "__main__":
    plot_optimized_system()