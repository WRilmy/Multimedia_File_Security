import numpy as np
from scipy.integrate import odeint
import random
import copy
import time

# 设置随机种子以保证结果可复现
np.random.seed(42)
random.seed(42)

# ============================================
# 1. 定义超混沌Chen系统（六参数版本）
# ============================================
def hyperchaotic_chen(state, t, a, b, c, d, r, e):
    """
    六参数超混沌Chen系统
    在经典四维Chen系统基础上，在dz/dt方程中添加e*w项
    """
    x, y, z, w = state
    dxdt = a * (y - x) + w
    dydt = d * x - x * z + c * y
    dzdt = x * y - b * z + e * w  # 调优：添加e*w项
    dwdt = x * z + r * w
    return [dxdt, dydt, dzdt, dwdt]

# ============================================
# 2. 计算李雅普诺夫指数（Wolf方法）
# ============================================
def compute_lyapunov_exponents(params, initial_state=None, t_max=100.0, dt=0.01):
    """
    使用Wolf方法计算四维系统的李雅普诺夫指数谱
    
    参数:
        params: (a, b, c, d, r, e) 系统参数
        initial_state: 初始状态，默认使用[0.1179, 0.2318, 0.3361, 0.4517]
        t_max: 积分总时间
        dt: 时间步长
    
    返回:
        lyapunov_exponents: 四个李雅普诺夫指数 [LE1, LE2, LE3, LE4]
    """
    a, b, c, d, r, e = params
    
    if initial_state is None:
        initial_state = [0.1179, 0.2318, 0.3361, 0.4517]
    
    # 时间数组
    t = np.arange(0, t_max, dt)
    n_steps = len(t)
    
    # 预热时间（让系统进入吸引子）
    warmup_steps = int(50.0 / dt)  # 预热50个时间单位
    
    # 主轨迹积分
    solution = odeint(hyperchaotic_chen, initial_state, t, args=(a, b, c, d, r, e))
    
    # 检查是否发散
    if np.any(np.isnan(solution)) or np.any(np.isinf(solution)):
        return [-100, -100, -100, -100]  # 返回很大的负值表示发散
    
    # 获取预热后的轨迹
    if n_steps > warmup_steps:
        trajectory = solution[warmup_steps:]
        t_valid = t[warmup_steps:]
    else:
        trajectory = solution
        t_valid = t
    
    n_valid = len(trajectory)
    if n_valid < 100:
        return [-100, -100, -100, -100]
    
    # Wolf方法计算李雅普诺夫指数
    # 初始化四个正交向量
    Q = np.eye(4)
    
    # 累积和用于计算LE
    lyap_sum = np.zeros(4)
    
    # 计算步长
    compute_interval = 10  # 每10步计算一次
    n_compute = 0
    
    for i in range(0, n_valid - compute_interval, compute_interval):
        # 当前状态
        state = trajectory[i]
        
        # 计算Jacobian矩阵
        x, y, z, w = state
        J = np.array([
            [-a, a, 0, 1],
            [d - z, c, -x, 0],
            [y, x, -b, e],
            [z, 0, x, r]
        ])
        
        # 演化正交向量
        for j in range(4):
            Q[:, j] = Q[:, j] + dt * compute_interval * J @ Q[:, j]
        
        # Gram-Schmidt正交化
        for j in range(4):
            for k in range(j):
                Q[:, j] = Q[:, j] - np.dot(Q[:, j], Q[:, k]) / np.dot(Q[:, k], Q[:, k]) * Q[:, k]
            
            # 计算范数
            norm = np.linalg.norm(Q[:, j])
            if norm > 1e-10:
                lyap_sum[j] += np.log(norm)
                Q[:, j] = Q[:, j] / norm
            else:
                lyap_sum[j] += np.log(1e-10)
        
        n_compute += 1
    
    # 计算平均李雅普诺夫指数
    if n_compute > 0:
        lyapunov_exponents = lyap_sum / (n_compute * dt * compute_interval)
    else:
        lyapunov_exponents = np.zeros(4)
    
    # 按降序排列
    lyapunov_exponents = np.sort(lyapunov_exponents)[::-1]
    
    return lyapunov_exponents

# ============================================
# 3. 定义适应度函数（优化目标）
# ============================================
def fitness_function(params):
    """
    计算一组参数的适应度值
    
    优化目标（按优先级排序）：
    1. 至少有两个正的李雅普诺夫指数（超混沌）
    2. 最大化最大李雅普诺夫指数（LE1）
    3. 最小化李雅普诺夫指数之和（接近0表示保守系统）
    4. 最大化Kaplan-Yorke维度
    
    返回:
        fitness: 适应度值（越大越好）
        le: 李雅普诺夫指数数组
        details: 详细信息字典
    """
    try:
        # 计算李雅普诺夫指数
        le = compute_lyapunov_exponents(params, t_max=80.0, dt=0.01)
        
        # 检查是否发散
        if le[0] < -50:
            return -1000, le, {"status": "diverged"}
        
        # 计算正的李雅普诺夫指数数量
        positive_le_count = np.sum(le > 0.01)
        
        # 计算李雅普诺夫指数之和
        le_sum = np.sum(le)
        
        # 计算Kaplan-Yorke维度
        # D_KY = j + sum(le[0:j]) / |le[j]|
        # 其中j是使sum(le[0:j]) >= 0的最大整数
        le_cumsum = np.cumsum(le)
        j = 0
        for i in range(4):
            if le_cumsum[i] >= 0:
                j = i + 1
        
        if j > 0 and j < 4 and le[j] < 0:
            d_ky = j + le_cumsum[j-1] / abs(le[j])
        elif j == 4:
            d_ky = 4.0
        else:
            d_ky = 0.0
        
        # 适应度计算
        fitness = 0.0
        
        # 必须有至少2个正的李雅普诺夫指数（超混沌）
        if positive_le_count >= 2:
            fitness += 1000.0  # 基础分
            
            # 最大化最大李雅普诺夫指数
            fitness += le[0] * 50.0
            
            # 最大化第二个正的李雅普诺夫指数
            if le[1] > 0:
                fitness += le[1] * 30.0
            
            # 最大化Kaplan-Yorke维度（接近4最好）
            fitness += d_ky * 20.0
            
            # 李雅普诺夫指数之和应接近0（保守系统特性）
            fitness -= abs(le_sum) * 5.0
            
            # 惩罚LE1过大（避免数值不稳定）
            if le[0] > 5.0:
                fitness -= (le[0] - 5.0) * 10.0
        else:
            # 不是超混沌，给予惩罚
            fitness = positive_le_count * 100.0 + le[0] * 10.0
        
        details = {
            "status": "ok",
            "positive_le_count": positive_le_count,
            "le_sum": le_sum,
            "d_ky": d_ky,
            "le": le
        }
        
        return fitness, le, details
        
    except Exception as e:
        return -1000, np.zeros(4), {"status": "error", "error": str(e)}

# ============================================
# 4. 粒子群优化（PSO）算法
# ============================================
class Particle:
    """粒子类"""
    def __init__(self, dim, bounds):
        self.position = np.array([random.uniform(bounds[i][0], bounds[i][1]) for i in range(dim)])
        self.velocity = np.array([random.uniform(-1, 1) for _ in range(dim)])
        self.best_position = self.position.copy()
        self.best_fitness = -float('inf')
        self.current_fitness = -float('inf')
        self.le = np.zeros(4)

class PSO:
    """粒子群优化算法"""
    def __init__(self, dim, bounds, n_particles=30, max_iter=100, 
                 w=0.7, c1=1.5, c2=1.5):
        """
        参数:
            dim: 维度（6个参数）
            bounds: 参数范围 [(min1, max1), ...]
            n_particles: 粒子数量
            max_iter: 最大迭代次数
            w: 惯性权重
            c1: 个体学习因子
            c2: 社会学习因子
        """
        self.dim = dim
        self.bounds = bounds
        self.n_particles = n_particles
        self.max_iter = max_iter
        self.w = w
        self.c1 = c1
        self.c2 = c2
        
        # 初始化粒子群
        self.particles = [Particle(dim, bounds) for _ in range(n_particles)]
        self.global_best_position = None
        self.global_best_fitness = -float('inf')
        self.global_best_le = np.zeros(4)
        
        # 记录历史最优
        self.history = []
    
    def optimize(self):
        """执行优化"""
        print("="*70)
        print("开始粒子群优化（PSO）")
        print("="*70)
        print(f"粒子数量: {self.n_particles}")
        print(f"最大迭代次数: {self.max_iter}")
        print(f"参数维度: {self.dim}")
        print(f"参数范围:")
        param_names = ['a', 'b', 'c', 'd', 'r', 'e']
        for i, (name, (lb, ub)) in enumerate(zip(param_names, self.bounds)):
            print(f"  {name}: [{lb:.2f}, {ub:.2f}]")
        print("="*70)
        
        start_time = time.time()
        
        for iteration in range(self.max_iter):
            iter_start = time.time()
            
            # 评估每个粒子
            for i, particle in enumerate(self.particles):
                fitness, le, details = fitness_function(particle.position)
                particle.current_fitness = fitness
                particle.le = le
                
                # 更新个体最优
                if fitness > particle.best_fitness:
                    particle.best_fitness = fitness
                    particle.best_position = particle.position.copy()
                
                # 更新全局最优
                if fitness > self.global_best_fitness:
                    self.global_best_fitness = fitness
                    self.global_best_position = particle.position.copy()
                    self.global_best_le = le.copy()
            
            # 记录历史
            self.history.append({
                'iteration': iteration + 1,
                'best_fitness': self.global_best_fitness,
                'best_params': self.global_best_position.copy(),
                'best_le': self.global_best_le.copy()
            })
            
            # 更新粒子速度和位置
            for particle in self.particles:
                r1 = np.random.random(self.dim)
                r2 = np.random.random(self.dim)
                
                # 更新速度
                particle.velocity = (self.w * particle.velocity + 
                                    self.c1 * r1 * (particle.best_position - particle.position) +
                                    self.c2 * r2 * (self.global_best_position - particle.position))
                
                # 限制速度
                v_max = [(self.bounds[i][1] - self.bounds[i][0]) * 0.2 for i in range(self.dim)]
                for i in range(self.dim):
                    particle.velocity[i] = np.clip(particle.velocity[i], -v_max[i], v_max[i])
                
                # 更新位置
                particle.position = particle.position + particle.velocity
                
                # 边界处理（反射边界）
                for i in range(self.dim):
                    if particle.position[i] < self.bounds[i][0]:
                        particle.position[i] = self.bounds[i][0] + (self.bounds[i][0] - particle.position[i])
                        particle.velocity[i] = -particle.velocity[i]
                    elif particle.position[i] > self.bounds[i][1]:
                        particle.position[i] = self.bounds[i][1] - (particle.position[i] - self.bounds[i][1])
                        particle.velocity[i] = -particle.velocity[i]
            
            # 动态调整惯性权重
            self.w = 0.9 - (0.5 * iteration / self.max_iter)
            
            # 打印进度
            iter_time = time.time() - iter_start
            if (iteration + 1) % 10 == 0 or iteration == 0:
                print(f"\n迭代 {iteration + 1}/{self.max_iter} (耗时: {iter_time:.2f}s)")
                print(f"  当前最优适应度: {self.global_best_fitness:.4f}")
                print(f"  最优参数: a={self.global_best_position[0]:.4f}, "
                      f"b={self.global_best_position[1]:.4f}, "
                      f"c={self.global_best_position[2]:.4f}, "
                      f"d={self.global_best_position[3]:.4f}, "
                      f"r={self.global_best_position[4]:.4f}, "
                      f"e={self.global_best_position[5]:.4f}")
                print(f"  李雅普诺夫指数: {self.global_best_le}")
                print(f"  正LE数量: {np.sum(self.global_best_le > 0.01)}")
        
        total_time = time.time() - start_time
        print("\n" + "="*70)
        print("优化完成！")
        print(f"总耗时: {total_time:.2f}秒")
        print("="*70)
        
        return self.global_best_position, self.global_best_fitness, self.global_best_le

# ============================================
# 5. 遗传算法（GA）
# ============================================
class GeneticAlgorithm:
    """遗传算法"""
    def __init__(self, dim, bounds, population_size=50, max_generations=100,
                 crossover_rate=0.8, mutation_rate=0.1, elitism=5):
        """
        参数:
            dim: 维度
            bounds: 参数范围
            population_size: 种群大小
            max_generations: 最大代数
            crossover_rate: 交叉概率
            mutation_rate: 变异概率
            elitism: 保留精英数量
        """
        self.dim = dim
        self.bounds = bounds
        self.population_size = population_size
        self.max_generations = max_generations
        self.crossover_rate = crossover_rate
        self.mutation_rate = mutation_rate
        self.elitism = elitism
        
        # 初始化种群
        self.population = []
        for _ in range(population_size):
            individual = np.array([random.uniform(bounds[i][0], bounds[i][1]) for i in range(dim)])
            self.population.append(individual)
        
        self.best_individual = None
        self.best_fitness = -float('inf')
        self.best_le = np.zeros(4)
        self.history = []
    
    def optimize(self):
        """执行优化"""
        print("="*70)
        print("开始遗传算法（GA）优化")
        print("="*70)
        print(f"种群大小: {self.population_size}")
        print(f"最大代数: {self.max_generations}")
        print(f"交叉概率: {self.crossover_rate}")
        print(f"变异概率: {self.mutation_rate}")
        print(f"精英保留: {self.elitism}")
        print("="*70)
        
        start_time = time.time()
        
        for generation in range(self.max_generations):
            gen_start = time.time()
            
            # 评估种群
            fitness_values = []
            le_values = []
            for individual in self.population:
                fitness, le, _ = fitness_function(individual)
                fitness_values.append(fitness)
                le_values.append(le)
            
            fitness_values = np.array(fitness_values)
            
            # 更新最优个体
            best_idx = np.argmax(fitness_values)
            if fitness_values[best_idx] > self.best_fitness:
                self.best_fitness = fitness_values[best_idx]
                self.best_individual = self.population[best_idx].copy()
                self.best_le = le_values[best_idx].copy()
            
            # 记录历史
            self.history.append({
                'generation': generation + 1,
                'best_fitness': self.best_fitness,
                'best_params': self.best_individual.copy(),
                'best_le': self.best_le.copy(),
                'avg_fitness': np.mean(fitness_values)
            })
            
            # 选择（锦标赛选择）
            selected = self.tournament_selection(fitness_values)
            
            # 创建新一代
            new_population = []
            
            # 精英保留
            sorted_indices = np.argsort(fitness_values)[::-1]
            for i in range(self.elitism):
                new_population.append(self.population[sorted_indices[i]].copy())
            
            # 交叉和变异
            while len(new_population) < self.population_size:
                parent1 = self.population[random.choice(selected)]
                parent2 = self.population[random.choice(selected)]
                
                if random.random() < self.crossover_rate:
                    child1, child2 = self.crossover(parent1, parent2)
                else:
                    child1, child2 = parent1.copy(), parent2.copy()
                
                child1 = self.mutate(child1)
                child2 = self.mutate(child2)
                
                new_population.append(child1)
                if len(new_population) < self.population_size:
                    new_population.append(child2)
            
            self.population = new_population[:self.population_size]
            
            # 打印进度
            gen_time = time.time() - gen_start
            if (generation + 1) % 10 == 0 or generation == 0:
                print(f"\n代数 {generation + 1}/{self.max_generations} (耗时: {gen_time:.2f}s)")
                print(f"  当前最优适应度: {self.best_fitness:.4f}")
                print(f"  平均适应度: {np.mean(fitness_values):.4f}")
                print(f"  最优参数: a={self.best_individual[0]:.4f}, "
                      f"b={self.best_individual[1]:.4f}, "
                      f"c={self.best_individual[2]:.4f}, "
                      f"d={self.best_individual[3]:.4f}, "
                      f"r={self.best_individual[4]:.4f}, "
                      f"e={self.best_individual[5]:.4f}")
                print(f"  李雅普诺夫指数: {self.best_le}")
                print(f"  正LE数量: {np.sum(self.best_le > 0.01)}")
        
        total_time = time.time() - start_time
        print("\n" + "="*70)
        print("优化完成！")
        print(f"总耗时: {total_time:.2f}秒")
        print("="*70)
        
        return self.best_individual, self.best_fitness, self.best_le
    
    def tournament_selection(self, fitness_values, tournament_size=3):
        """锦标赛选择"""
        selected = []
        for _ in range(self.population_size):
            tournament = random.sample(range(self.population_size), tournament_size)
            winner = max(tournament, key=lambda i: fitness_values[i])
            selected.append(winner)
        return selected
    
    def crossover(self, parent1, parent2):
        """模拟二进制交叉（SBX）"""
        child1 = np.zeros(self.dim)
        child2 = np.zeros(self.dim)
        
        eta = 20.0  # 分布指数
        
        for i in range(self.dim):
            if random.random() <= 0.5:
                if abs(parent1[i] - parent2[i]) > 1e-14:
                    if parent1[i] < parent2[i]:
                        y1, y2 = parent1[i], parent2[i]
                    else:
                        y1, y2 = parent2[i], parent1[i]
                    
                    beta = 1.0 + (2.0 * (y1 - self.bounds[i][0]) / (y2 - y1))
                    alpha = 2.0 - beta ** (-(eta + 1.0))
                    
                    rand = random.random()
                    if rand <= 1.0 / alpha:
                        beta_q = (rand * alpha) ** (1.0 / (eta + 1.0))
                    else:
                        beta_q = (1.0 / (2.0 - rand * alpha)) ** (1.0 / (eta + 1.0))
                    
                    c1 = 0.5 * ((y1 + y2) - beta_q * (y2 - y1))
                    
                    beta = 1.0 + (2.0 * (self.bounds[i][1] - y2) / (y2 - y1))
                    alpha = 2.0 - beta ** (-(eta + 1.0))
                    
                    if rand <= 1.0 / alpha:
                        beta_q = (rand * alpha) ** (1.0 / (eta + 1.0))
                    else:
                        beta_q = (1.0 / (2.0 - rand * alpha)) ** (1.0 / (eta + 1.0))
                    
                    c2 = 0.5 * ((y1 + y2) + beta_q * (y2 - y1))
                    
                    child1[i] = np.clip(c1, self.bounds[i][0], self.bounds[i][1])
                    child2[i] = np.clip(c2, self.bounds[i][0], self.bounds[i][1])
                else:
                    child1[i] = parent1[i]
                    child2[i] = parent2[i]
            else:
                child1[i] = parent1[i]
                child2[i] = parent2[i]
        
        return child1, child2
    
    def mutate(self, individual):
        """多项式变异"""
        eta_m = 20.0  # 变异分布指数
        
        for i in range(self.dim):
            if random.random() < self.mutation_rate:
                y = individual[i]
                yl, yu = self.bounds[i][0], self.bounds[i][1]
                
                if yl == yu:
                    continue
                
                delta1 = (y - yl) / (yu - yl)
                delta2 = (yu - y) / (yu - yl)
                
                rand = random.random()
                mut_pow = 1.0 / (eta_m + 1.0)
                
                if rand <= 0.5:
                    xy = 1.0 - delta1
                    val = 2.0 * rand + (1.0 - 2.0 * rand) * (xy ** (eta_m + 1.0))
                    delta_q = val ** mut_pow - 1.0
                else:
                    xy = 1.0 - delta2
                    val = 2.0 * (1.0 - rand) + 2.0 * (rand - 0.5) * (xy ** (eta_m + 1.0))
                    delta_q = 1.0 - val ** mut_pow
                
                y = y + delta_q * (yu - yl)
                individual[i] = np.clip(y, yl, yu)
        
        return individual

# ============================================
# 6. 主程序
# ============================================
def main():
    """主函数"""
    print("="*70)
    print("六参数超混沌Chen系统参数优化工具")
    print("="*70)
    print("\n本工具使用粒子群优化（PSO）和遗传算法（GA）")
    print("寻找能使李雅普诺夫指数最优的参数组合。")
    print("\n优化目标：")
    print("  1. 至少有两个正的李雅普诺夫指数（超混沌）")
    print("  2. 最大化最大李雅普诺夫指数")
    print("  3. 最大化Kaplan-Yorke维度")
    print("="*70)
    
    # 参数范围设置
    # 基于经典Chen系统和文献经验设置合理的搜索范围
    bounds = [
        (20.0, 50.0),   # a: 通常较大
        (1.0, 10.0),    # b: 中等大小
        (5.0, 30.0),    # c: 可变范围大
        (5.0, 20.0),    # d: 中等大小
        (0.1, 1.0),     # r: 较小值
        (0.0, 5.0)      # e: 新增参数，耦合强度
    ]
    
    dim = 6
    
    # 选择优化算法
    print("\n请选择优化算法：")
    print("  1. 粒子群优化（PSO）- 收敛快，适合连续优化")
    print("  2. 遗传算法（GA）- 全局搜索能力强，适合复杂问题")
    print("  3. 两种算法都运行")
    
    try:
        choice = input("\n请输入选项 (1/2/3，默认3): ").strip()
        if not choice:
            choice = '3'
    except:
        choice = '3'
    
    results = {}
    
    # 运行PSO
    if choice in ['1', '3']:
        print("\n" + "="*70)
        print("运行粒子群优化（PSO）")
        print("="*70)
        
        pso = PSO(dim, bounds, n_particles=30, max_iter=100)
        pso_best_params, pso_best_fitness, pso_best_le = pso.optimize()
        
        results['PSO'] = {
            'params': pso_best_params,
            'fitness': pso_best_fitness,
            'le': pso_best_le
        }
    
    # 运行GA
    if choice in ['2', '3']:
        print("\n" + "="*70)
        print("运行遗传算法（GA）")
        print("="*70)
        
        ga = GeneticAlgorithm(dim, bounds, population_size=50, max_generations=100)
        ga_best_params, ga_best_fitness, ga_best_le = ga.optimize()
        
        results['GA'] = {
            'params': ga_best_params,
            'fitness': ga_best_fitness,
            'le': ga_best_le
        }
    
    # 输出最终结果
    print("\n" + "="*70)
    print("优化结果汇总")
    print("="*70)
    
    for method, result in results.items():
        print(f"\n【{method}】")
        print(f"  最优适应度: {result['fitness']:.4f}")
        print(f"  最优参数:")
        param_names = ['a', 'b', 'c', 'd', 'r', 'e']
        for i, name in enumerate(param_names):
            print(f"    {name} = {result['params'][i]:.6f}")
        print(f"  李雅普诺夫指数: {result['le']}")
        print(f"  正LE数量: {np.sum(result['le'] > 0.01)}")
        
        # 计算Kaplan-Yorke维度
        le = result['le']
        le_cumsum = np.cumsum(le)
        j = 0
        for i in range(4):
            if le_cumsum[i] >= 0:
                j = i + 1
        
        if j > 0 and j < 4 and le[j] < 0:
            d_ky = j + le_cumsum[j-1] / abs(le[j])
        elif j == 4:
            d_ky = 4.0
        else:
            d_ky = 0.0
        
        print(f"  Kaplan-Yorke维度: {d_ky:.4f}")
    
    # 选择最优结果
    if len(results) > 1:
        best_method = max(results.keys(), key=lambda k: results[k]['fitness'])
        best_result = results[best_method]
        
        print("\n" + "="*70)
        print(f"最终推荐参数（来自{best_method}）")
        print("="*70)
        print(f"  适应度: {best_result['fitness']:.4f}")
        print(f"  参数配置:")
        for i, name in enumerate(param_names):
            print(f"    {name} = {best_result['params'][i]:.6f}")
        print(f"  李雅普诺夫指数: {best_result['le']}")
        print(f"  正LE数量: {np.sum(best_result['le'] > 0.01)}")
    
    print("\n" + "="*70)
    print("优化完成！")
    print("="*70)
    print("\n提示：")
    print("  - 可以将最优参数复制到HyperchaoticChenOptimizedUtil.java中")
    print("  - 建议多次运行取平均，或微调参数范围后重新优化")
    print("="*70)

if __name__ == "__main__":
    main()
