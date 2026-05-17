package org.example.multimedia_file_security.controller;

import lombok.extern.slf4j.Slf4j;
import org.example.multimedia_file_security.dto.Result;
import org.example.multimedia_file_security.utils.HyperchaoticChenOptimizedUtil;
import org.example.multimedia_file_security.utils.HyperchaoticChenUtil;
import org.example.multimedia_file_security.utils.NistRandomnessTestUtil;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.*;

import static java.lang.Thread.sleep;

/**
 * Lyapunov指数计算控制器
 * 提供超混沌Chen系统的Lyapunov指数计算接口
 */
@RestController
@Slf4j
@RequestMapping("/lyapunov")
public class LyapunovController {

    /**
     * 返回超混沌吸引子图片。
     * type=standard 返回标准版 Chen 系统，type=optimized 返回改进版 Chen 系统。
     */
    @GetMapping(value = "/attractor-image", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> getAttractorImage(
            @RequestParam(value = "type", defaultValue = "standard") String type) throws IOException {
        String resourcePath = switch (type == null ? "" : type.toLowerCase(Locale.ROOT)) {
            case "standard" -> "chaos-images/standard-attractor.png";
            case "optimized" -> "chaos-images/optimized-attractor.png";
            default -> null;
        };

        if (resourcePath == null) {
            return ResponseEntity.badRequest().build();
        }

        ClassPathResource resource = new ClassPathResource(resourcePath);
        if (!resource.exists()) {
            log.warn("超混沌吸引子图片不存在: {}", resourcePath);
            return ResponseEntity.notFound().build();
        }

        byte[] imageBytes;
        try (InputStream inputStream = resource.getInputStream()) {
            imageBytes = inputStream.readAllBytes();
        }
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_PNG);
        headers.setContentLength(imageBytes.length);
        headers.setCacheControl(CacheControl.maxAge(Duration.ofDays(30)).cachePublic());

        return ResponseEntity.ok()
                .headers(headers)
                .body(imageBytes);
    }

    /**
     * 计算标准版四维超混沌Chen系统的Lyapunov指数
     */
    @GetMapping("/chen")
    public Result<Map<String, Object>> calculateChenLyapunov() {
        try {
            log.info("开始计算标准版超混沌Chen系统的Lyapunov指数");
            
            HyperchaoticChenUtil.ChenKeyStreamConfig config = 
                HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();
            
            double[] exponents = HyperchaoticChenUtil.calculateLyapunovExponents(
                config, 10000, 50000, 100
            );
            
            Map<String, Object> result = buildLyapunovResult(
                exponents, "标准版四维超混沌Chen系统", config
            );
            
            log.info("标准版Lyapunov指数计算完成: {}", Arrays.toString(exponents));
            return Result.success("计算成功", result);
            
        } catch (Exception e) {
            log.error("标准版Lyapunov指数计算失败", e);
            return Result.error(500, "计算失败: " + e.getMessage());
        }
    }

    /**
     * 计算改进版四维超混沌Chen系统的Lyapunov指数
     */
    @GetMapping("/chen-optimized")
    public Result<Map<String, Object>> calculateOptimizedChenLyapunov() {
        try {
            log.info("开始计算改进版超混沌Chen系统的Lyapunov指数");
            
            HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = 
                HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig.defaultConfig();
            
            double[] exponents = HyperchaoticChenOptimizedUtil.calculateLyapunovExponents(
                config, 10000, 50000, 100
            );
            
            Map<String, Object> result = buildOptimizedLyapunovResult(
                exponents, "改进版四维超混沌Chen系统", config
            );
            
            log.info("改进版Lyapunov指数计算完成: {}", Arrays.toString(exponents));
            return Result.success("计算成功", result);
            
        } catch (Exception e) {
            log.error("改进版Lyapunov指数计算失败", e);
            return Result.error(500, "计算失败: " + e.getMessage());
        }
    }

    /**
     * 生成改进版超混沌 Chen 密钥流并执行 NIST 随机性测试。
     *
     * @param lengthBytes 测试样本长度，单位字节，后端会限制在 1KB 到 1MB 之间
     * @param configType 参数配置类型，支持 default、highCoupling/highLyapunov 和 negativeFeedback
     * @return 密钥流参数、NIST 测试列表和汇总结果
     */
    @GetMapping("/nist-key-stream")
    public Result<Map<String, Object>> testOptimizedChenKeyStreamNist(
            @RequestParam(value = "lengthBytes", defaultValue = "131072") int lengthBytes,
            @RequestParam(value = "configType", defaultValue = "default") String configType) {
        try {
            int safeLength = Math.max(1024, Math.min(lengthBytes, 1024 * 1024));
            HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config = buildOptimizedConfig(configType);
            byte[] keyStream = HyperchaoticChenOptimizedUtil.generateKeyStream(safeLength, config);

            Map<String, Object> nistResult = NistRandomnessTestUtil.runKeyStreamTests(keyStream);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("configType", configType);
            result.put("lengthBytes", safeLength);
            result.put("lengthBits", safeLength * 8L);
            result.put("parameters", buildOptimizedParameters(config));
            result.putAll(nistResult);

            return Result.success("NIST key stream test completed", result);
        } catch (Exception e) {
            log.error("NIST key stream test failed", e);
            return Result.error(500, "NIST key stream test failed: " + e.getMessage());
        }
    }

    /**
     * 对比两个版本的Lyapunov指数
     */
    @GetMapping("/compare")
    public Result<Map<String, Object>> compareLyapunov() {
        try {
            log.info("开始对比两个版本的Lyapunov指数");
            
            // 计算标准版
            HyperchaoticChenUtil.ChenKeyStreamConfig config1 = 
                HyperchaoticChenUtil.ChenKeyStreamConfig.defaultConfig();
            double[] exponents1 = HyperchaoticChenUtil.calculateLyapunovExponents(
                config1, 10000, 50000, 100
            );
            
            // 计算改进版
            HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config2 = 
                HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig.defaultConfig();
            double[] exponents2 = HyperchaoticChenOptimizedUtil.calculateLyapunovExponents(
                config2, 10000, 50000, 100
            );
            
            Map<String, Object> comparison = new HashMap<>();
            comparison.put("standard", buildLyapunovResult(exponents1, "标准版", config1));
            comparison.put("optimized", buildOptimizedLyapunovResult(exponents2, "改进版", config2));
            
            // 计算差异
            Map<String, Object> differences = new HashMap<>();
            differences.put("lambda1_diff", exponents2[0] - exponents1[0]);
            differences.put("lambda2_diff", exponents2[1] - exponents1[1]);
            differences.put("lambda3_diff", exponents2[2] - exponents1[2]);
            differences.put("lambda4_diff", exponents2[3] - exponents1[3]);
            differences.put("positive_count_standard", countPositive(exponents1));
            differences.put("positive_count_optimized", countPositive(exponents2));
            comparison.put("differences", differences);
            
            log.info("Lyapunov指数对比完成");
            return Result.success("对比成功", comparison);
            
        } catch (Exception e) {
            log.error("Lyapunov指数对比失败", e);
            return Result.error(500, "对比失败: " + e.getMessage());
        }
    }

    /**
     * 使用自定义参数计算Lyapunov指数
     */
    @PostMapping("/calculate")
    public Result<Map<String, Object>> calculateWithParams(@RequestBody Map<String, Object> params) {
        try {
            log.info("使用自定义参数计算Lyapunov指数: {}", params);
            
            double a = getDoubleParam(params, "a", 35.0);
            double b = getDoubleParam(params, "b", 3.0);
            double c = getDoubleParam(params, "c", 12.0);
            double d = getDoubleParam(params, "d", 7.0);
            double r = getDoubleParam(params, "r", 0.5);
            double x0 = getDoubleParam(params, "x0", 0.1179);
            double y0 = getDoubleParam(params, "y0", 0.2318);
            double z0 = getDoubleParam(params, "z0", 0.3361);
            double w0 = getDoubleParam(params, "w0", 0.4517);
            double stepSize = getDoubleParam(params, "stepSize", 0.001);
            int warmupSteps = getIntParam(params, "warmupSteps", 10000);
            int integrationSteps = getIntParam(params, "integrationSteps", 50000);
            
            HyperchaoticChenUtil.ChenKeyStreamConfig config = 
                new HyperchaoticChenUtil.ChenKeyStreamConfig(
                    a, b, c, d, r, x0, y0, z0, w0, stepSize, 4000, 3
                );
            
            double[] exponents = HyperchaoticChenUtil.calculateLyapunovExponents(
                config, warmupSteps, integrationSteps, 100
            );
            
            Map<String, Object> result = buildLyapunovResult(
                exponents, "自定义参数超混沌Chen系统", config
            );
            
            return Result.success("计算成功", result);
            
        } catch (Exception e) {
            log.error("自定义参数Lyapunov指数计算失败", e);
            return Result.error(500, "计算失败: " + e.getMessage());
        }
    }

    /**
     * 将标准 Chen 系统的 Lyapunov 指数和参数组装为前端可展示的数据结构。
     *
     * @param exponents Lyapunov 指数数组
     * @param version 系统版本名称
     * @param config 标准 Chen 系统配置
     * @return 前端展示用结果 Map
     */
    private Map<String, Object> buildLyapunovResult(double[] exponents, String version, 
                                                     HyperchaoticChenUtil.ChenKeyStreamConfig config) {
        Map<String, Object> result = new HashMap<>();
        
        // 基本信息
        result.put("version", version);
        result.put("dimension", 4);
        result.put("positiveCount", countPositive(exponents));
        
        // Lyapunov指数详情
        List<Map<String, Object>> exponentList = new ArrayList<>();
        for (int i = 0; i < exponents.length; i++) {
            Map<String, Object> exp = new HashMap<>();
            exp.put("index", i + 1);
            exp.put("symbol", "λ" + (i + 1));
            exp.put("value", exponents[i]);
            exp.put("isPositive", exponents[i] > 0);
            exponentList.add(exp);
        }
        result.put("exponents", exponentList);
        
        // 系统参数
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("a", config.getA());
        parameters.put("b", config.getB());
        parameters.put("c", config.getC());
        parameters.put("d", config.getD());
        parameters.put("r", config.getR());
        parameters.put("x0", config.getX0());
        parameters.put("y0", config.getY0());
        parameters.put("z0", config.getZ0());
        parameters.put("w0", config.getW0());
        parameters.put("stepSize", config.getStepSize());
        result.put("parameters", parameters);
        
        // 混沌特性判断
        result.put("isHyperchaotic", countPositive(exponents) >= 2);
        result.put("isChaotic", countPositive(exponents) >= 1);
        result.put("kaplanYorkeDimension", calculateKaplanYorke(exponents));
        
        return result;
    }

    /**
     * 将改进版 Chen 系统的 Lyapunov 指数和参数组装为前端可展示的数据结构。
     *
     * @param exponents Lyapunov 指数数组
     * @param version 系统版本名称
     * @param config 改进版 Chen 系统配置
     * @return 前端展示用结果 Map
     */
    private Map<String, Object> buildOptimizedLyapunovResult(double[] exponents, String version,
                                                              HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) {
        Map<String, Object> result = new HashMap<>();
        
        result.put("version", version);
        result.put("dimension", 4);
        result.put("positiveCount", countPositive(exponents));
        
        List<Map<String, Object>> exponentList = new ArrayList<>();
        for (int i = 0; i < exponents.length; i++) {
            Map<String, Object> exp = new HashMap<>();
            exp.put("index", i + 1);
            exp.put("symbol", "λ" + (i + 1));
            exp.put("value", exponents[i]);
            exp.put("isPositive", exponents[i] > 0);
            exponentList.add(exp);
        }
        result.put("exponents", exponentList);
        
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("a", config.getA());
        parameters.put("b", config.getB());
        parameters.put("c", config.getC());
        parameters.put("d", config.getD());
        parameters.put("e", config.getE());  // 改进版特有参数
        parameters.put("r", config.getR());
        parameters.put("x0", config.getX0());
        parameters.put("y0", config.getY0());
        parameters.put("z0", config.getZ0());
        parameters.put("w0", config.getW0());
        parameters.put("stepSize", config.getStepSize());
        result.put("parameters", parameters);
        
        result.put("isHyperchaotic", countPositive(exponents) >= 2);
        result.put("isChaotic", countPositive(exponents) >= 1);
        result.put("kaplanYorkeDimension", calculateKaplanYorke(exponents));
        
        return result;
    }

    /**
     * 根据前端传入的配置名称构造改进版 Chen 系统参数。
     *
     * @param configType 配置名称
     * @return 对应的改进版 Chen 密钥流配置
     */
    private HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig buildOptimizedConfig(String configType) {
        if ("highCoupling".equalsIgnoreCase(configType) || "highLyapunov".equalsIgnoreCase(configType)) {
            return HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig.highCouplingConfig();
        }
        if ("negativeFeedback".equalsIgnoreCase(configType)) {
            return HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig.negativeFeedbackConfig();
        }
        return HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig.defaultConfig();
    }

    /**
     * 提取改进版 Chen 系统参数，供 NIST 和 Lyapunov 前端模块展示。
     *
     * @param config 改进版 Chen 密钥流配置
     * @return 参数名到参数值的有序映射
     */
    private Map<String, Object> buildOptimizedParameters(HyperchaoticChenOptimizedUtil.ChenKeyStreamConfig config) {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("a", config.getA());
        parameters.put("b", config.getB());
        parameters.put("c", config.getC());
        parameters.put("d", config.getD());
        parameters.put("e", config.getE());
        parameters.put("r", config.getR());
        parameters.put("x0", config.getX0());
        parameters.put("y0", config.getY0());
        parameters.put("z0", config.getZ0());
        parameters.put("w0", config.getW0());
        parameters.put("stepSize", config.getStepSize());
        parameters.put("warmupIterations", config.getWarmupIterations());
        parameters.put("samplingStride", config.getSamplingStride());
        return parameters;
    }

    /**
     * 统计 Lyapunov 指数中大于 0 的数量。
     *
     * @param exponents Lyapunov 指数数组
     * @return 正 Lyapunov 指数个数
     */
    private int countPositive(double[] exponents) {
        int count = 0;
        for (double exp : exponents) {
            if (exp > 0) count++;
        }
        return count;
    }

    /**
     * 计算Kaplan-Yorke维度
     */
    private double calculateKaplanYorke(double[] exponents) {
        double sum = 0;
        int j = 0;
        
        // 按从大到小排序（应该已经是排序好的）
        double[] sorted = exponents.clone();
        Arrays.sort(sorted);
        // 反转使其从大到小
        for (int i = 0; i < sorted.length / 2; i++) {
            double temp = sorted[i];
            sorted[i] = sorted[sorted.length - 1 - i];
            sorted[sorted.length - 1 - i] = temp;
        }
        
        while (j < sorted.length && sum + sorted[j] >= 0) {
            sum += sorted[j];
            j++;
        }
        
        if (j == 0 || j >= sorted.length) {
            return sorted.length;
        }
        
        return j + sum / Math.abs(sorted[j]);
    }

    /**
     * 从请求参数中读取 double 值，缺失或类型不匹配时使用默认值。
     *
     * @param params 请求参数 Map
     * @param key 参数名
     * @param defaultValue 默认值
     * @return 解析后的 double 值
     */
    private double getDoubleParam(Map<String, Object> params, String key, double defaultValue) {
        if (params.containsKey(key)) {
            Object value = params.get(key);
            if (value instanceof Number) {
                return ((Number) value).doubleValue();
            }
        }
        return defaultValue;
    }

    /**
     * 从请求参数中读取 int 值，缺失或类型不匹配时使用默认值。
     *
     * @param params 请求参数 Map
     * @param key 参数名
     * @param defaultValue 默认值
     * @return 解析后的 int 值
     */
    private int getIntParam(Map<String, Object> params, String key, int defaultValue) {
        if (params.containsKey(key)) {
            Object value = params.get(key);
            if (value instanceof Number) {
                return ((Number) value).intValue();
            }
        }
        return defaultValue;
    }
}
